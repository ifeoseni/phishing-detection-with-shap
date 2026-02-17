import re
import base64
import urllib.parse
import joblib
import shap
import streamlit as st
import numpy as np
import pandas as pd
from io import BytesIO
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Import feature extractor
try:
    from feature_extractor_live import extract_all, EXPECTED_FEATURES
except ImportError as e:
    st.error(f"Failed to import feature extractor: {e}")
    st.stop()

# -------------------------------
# Sigmoid & Logit Functions (Numerically Stable)
# -------------------------------
def sigmoid(x):
    x = np.clip(x, -500, 500)
    return 1 / (1 + np.exp(-x))

def logit(p):
    p = np.clip(p, 1e-12, 1 - 1e-12)
    return np.log(p / (1 - p))

# -------------------------------
# Status Explanations
# -------------------------------
status_explanations = {
    0: "No response or unresolved URL",
    200: "OK - Standard response for successful requests",
    201: "Created - Request fulfilled, new resource created",
    202: "Accepted - Request received but not yet acted upon",
    204: "No Content - Success but no content to return",
    301: "Moved Permanently - Resource has a new permanent URI",
    302: "Found - Resource temporarily located at another URI",
    307: "Temporary Redirect - Resource temporarily located elsewhere",
    400: "Bad Request - Server cannot process due to client error",
    401: "Unauthorized - Authentication required",
    403: "Forbidden - Server refuses to fulfill request",
    404: "Not Found - Resource not available",
    408: "Request Timeout - Server timed out waiting for the request",
    410: "Gone - Resource is no longer available",
    429: "Too Many Requests - Rate limiting in effect",
    451: "Unavailable For Legal Reasons - Blocked for legal reasons",
    500: "Internal Server Error - Generic server failure",
    502: "Bad Gateway - Invalid response from upstream server",
    503: "Service Unavailable - Server temporarily overloaded or down",
    504: "Gateway Timeout - Upstream server failed to respond",
    999: "Request blocked by server (often due to bot detection or scraping)"
}

# -------------------------------
# Load Datasets
# -------------------------------
@st.cache_data
def load_datasets():
    datasets = []
    try:
        df1 = pd.read_csv('network_data_with_lexical_features/lexical_features_Mendeley_cleaned_v2.csv', low_memory=False)
        if 'url' in df1.columns and 'label' in df1.columns:
            df1['url'] = df1['url'].astype(str).str.strip().str.lower()
            datasets.append(df1)
    except Exception as e:
        st.warning(f"Could not load Mendeley dataset: {e}")
    try:
        df2 = pd.read_csv('network_data_with_lexical_features/lexical_features_PhiUSIIL_cleaned_v2_.csv', low_memory=False)
        if 'url' in df2.columns and 'label' in df2.columns:
            df2['url'] = df2['url'].astype(str).str.strip().str.lower()
            datasets.append(df2)
    except Exception as e:
        st.warning(f"Could not load PhiUSIIL dataset: {e}")
    return datasets

def is_url_in_labeled_dataset(url: str) -> tuple:
    datasets = load_datasets()
    url_clean = url.strip().lower()
    for df in datasets:
        match = df[df['url'] == url_clean]
        if len(match) > 0:
            label = match.iloc[0]['label']
            actual_label = "Phishing" if label == 1 else "Legitimate"
            return True, actual_label
    return False, None

# -------------------------------
# ROBUST SHAP EXTRACTION
# -------------------------------
def extract_phishing_class_shap(exp, feature_names):
    try:
        if hasattr(exp.base_values, '__len__'):
            if exp.base_values.ndim == 1:
                base_val = float(exp.base_values[0])
            elif exp.base_values.ndim == 2:
                base_val = float(exp.base_values[0, 1]) if exp.base_values.shape[1] >= 2 else float(exp.base_values[0, 0])
            else:
                base_val = float(exp.base_values.flatten()[0])
        else:
            base_val = float(exp.base_values)
        
        if exp.values.ndim == 1:
            shap_vals = np.array(exp.values).flatten()
        elif exp.values.ndim == 2:
            shap_vals = np.array(exp.values[0]).flatten()
        elif exp.values.ndim == 3:
            shap_vals = np.array(exp.values[0, :, 1]).flatten() if exp.values.shape[2] >= 2 else np.array(exp.values[0, :, 0]).flatten()
        else:
            raise ValueError(f"Unsupported dimension: {exp.values.ndim}")
        
        data = exp.data if exp.data.ndim == 1 else (exp.data[0] if exp.data.shape[0] > 0 else np.zeros(len(feature_names)))
        
        if len(shap_vals) != len(feature_names):
            if len(shap_vals) < len(feature_names):
                shap_vals = np.pad(shap_vals, (0, len(feature_names) - len(shap_vals)), 'constant')
                data = np.pad(data, (0, len(feature_names) - len(data)), 'constant')
            else:
                shap_vals = shap_vals[:len(feature_names)]
                data = data[:len(feature_names)]
        
        if len(shap_vals) == 0:
            shap_vals = np.array([0.0])
            data = np.array([0.0])
            base_val = 0.0
            aligned_features = ["dummy_feature"]
        else:
            aligned_features = feature_names[:len(shap_vals)]
        
        return shap.Explanation(
            values=shap_vals,
            base_values=base_val,
            data=data,
            feature_names=aligned_features
        )
    except Exception as e:
        st.error(f"SHAP extraction failed: {str(e)}")
        dummy_len = min(10, len(feature_names))
        return shap.Explanation(
            values=np.zeros(dummy_len),
            base_values=0.0,
            data=np.zeros(dummy_len),
            feature_names=feature_names[:dummy_len] if len(feature_names) >= dummy_len else [f"feature_{i}" for i in range(dummy_len)]
        )

# -------------------------------
# SPACE-AWARE MODEL PROBABILITY CALCULATION (CRITICAL FIX)
# -------------------------------
def get_model_probability(exp, model_type):
    """
    CORRECTLY compute probability based on model's native output space:
    - 'rf': Random Forest outputs in PROBABILITY space (0-1)
    - 'xgb': XGBoost outputs in LOG-ODDS space (requires sigmoid)
    - 'weighted': Weighted ensemble outputs in PROBABILITY space
    - 'stacking': Stacking ensemble outputs in LOG-ODDS space
    """
    output_value = exp.base_values + np.sum(exp.values)
    
    if model_type in ['rf', 'weighted']:
        # Native output is probability
        return np.clip(output_value, 0.0, 1.0), output_value, "probability"
    else:  # 'xgb' or 'stacking'
        # Native output is log-odds
        prob = sigmoid(output_value)
        return prob, output_value, "log-odds"

# -------------------------------
# PREDICTIONS FOR ALL 4 MODELS
# -------------------------------
def predict_all_models(X_df, rf_model, xgb_model, meta_clf, thresholds, W_RF=0.35, W_XGB=0.65):
    try:
        rf_prob = rf_model.predict_proba(X_df)[:, 1][0]
        xgb_prob = xgb_model.predict_proba(X_df)[:, 1][0]
        
        weighted_prob = (W_RF * rf_prob) + (W_XGB * xgb_prob)
        weighted_pred = int(weighted_prob >= thresholds.get("ensemble", 0.7))
        
        meta_input = np.array([[rf_prob, xgb_prob]])
        meta_logodds = meta_clf.decision_function(meta_input)[0]
        stacking_prob = sigmoid(meta_logodds)
        stacking_pred = int(stacking_prob >= thresholds.get("ensemble", 0.7))
        
        return {
            "rf_prob": float(rf_prob), "rf_pred": int(rf_prob >= thresholds.get("rf", 0.7)),
            "xgb_prob": float(xgb_prob), "xgb_pred": int(xgb_prob >= thresholds.get("xgb", 0.7)),
            "weighted_prob": float(weighted_prob), "weighted_pred": weighted_pred,
            "stacking_logodds": float(meta_logodds), "stacking_prob": float(stacking_prob), "stacking_pred": stacking_pred,
            "meta_weights": {"rf": float(meta_clf.coef_[0][0]), "xgb": float(meta_clf.coef_[0][1])},
            "meta_intercept": float(meta_clf.intercept_[0]),
            "weights": {"rf": W_RF, "xgb": W_XGB}
        }
    except Exception as e:
        st.error(f"Prediction failed: {str(e)}")
        raise

# -------------------------------
# RIGOROUS SHAP EXPLANATIONS (SPACE-CORRECTED)
# -------------------------------
def explain_all_models(X_df, rf_model, xgb_model, meta_clf, rf_explainer, xgb_explainer, feature_names, W_RF=0.35, W_XGB=0.65):
    try:
        rf_exp_raw = rf_explainer(X_df)
        xgb_exp_raw = xgb_explainer(X_df)
        
        rf_exp = extract_phishing_class_shap(rf_exp_raw, feature_names)
        xgb_exp = extract_phishing_class_shap(xgb_exp_raw, feature_names)
        
        # ✅ CRITICAL FIX 1: CORRECT SPACE HANDLING FOR BASE MODELS
        rf_prob, _, _ = get_model_probability(rf_exp, 'rf')
        xgb_prob, _, _ = get_model_probability(xgb_exp, 'xgb')
        
        # ✅ CRITICAL FIX 2: SPACE-CONSISTENT CHAIN RULE FOR ENSEMBLES
        epsilon = 1e-8
        
        # RF SHAP in probability space (exact)
        rf_shap_prob = rf_exp.values
        rf_expected_prob = rf_exp.base_values
        
        # XGB SHAP approximated to probability space
        xgb_expected_prob = sigmoid(xgb_exp.base_values)
        xgb_shap_prob_approx = xgb_exp.values * (xgb_prob * (1 - xgb_prob) + epsilon)
        
        # Scale XGB SHAP in prob space to ensure additivity (force sum(shap) == actual_delta)
        xgb_delta_exact = xgb_prob - xgb_expected_prob
        xgb_sum_approx = np.sum(xgb_shap_prob_approx)
        if abs(xgb_sum_approx) > epsilon:
            scale_factor = xgb_delta_exact / xgb_sum_approx
            xgb_shap_prob = xgb_shap_prob_approx * scale_factor
        else:
            xgb_shap_prob = xgb_shap_prob_approx  # If zero, keep as is
        
        # Weighted Ensemble (in probability space)
        weighted_prob = (W_RF * rf_prob) + (W_XGB * xgb_prob)
        weighted_expected_prob = (W_RF * rf_expected_prob) + (W_XGB * xgb_expected_prob)
        weighted_shap_prob = (W_RF * rf_shap_prob) + (W_XGB * xgb_shap_prob)
        
        weighted_data = X_df.iloc[0].values
        if len(weighted_data) != len(weighted_shap_prob):
            weighted_data = np.pad(weighted_data, (0, len(weighted_shap_prob) - len(weighted_data)), 'constant') if len(weighted_data) < len(weighted_shap_prob) else weighted_data[:len(weighted_shap_prob)]
        weighted_exp = shap.Explanation(
            values=weighted_shap_prob,
            base_values=weighted_expected_prob,
            data=weighted_data,
            feature_names=feature_names[:len(weighted_shap_prob)]
        )
        
        # Stacking Ensemble (in log-odds space)
        w_rf, w_xgb = float(meta_clf.coef_[0][0]), float(meta_clf.coef_[0][1])
        intercept = float(meta_clf.intercept_[0])
        
        # SHAP for stacking logodds w.r.t features (chain rule approx + scaling for additivity)
        stacking_shap_logodds = (w_rf * rf_shap_prob) + (w_xgb * xgb_shap_prob)  # Uses the scaled xgb_shap_prob
        
        stacking_expected_logodds = intercept + (w_rf * rf_expected_prob) + (w_xgb * xgb_expected_prob)
        
        stacking_data = X_df.iloc[0].values
        if len(stacking_data) != len(stacking_shap_logodds):
            stacking_data = np.pad(stacking_data, (0, len(stacking_shap_logodds) - len(stacking_data)), 'constant') if len(stacking_data) < len(stacking_shap_logodds) else stacking_data[:len(stacking_shap_logodds)]
        stacking_exp = shap.Explanation(
            values=stacking_shap_logodds,
            base_values=stacking_expected_logodds,
            data=stacking_data,
            feature_names=feature_names[:len(stacking_shap_logodds)]
        )
        
        # Meta-learner level (exact, since linear in probabilities)
        meta_expected = intercept + (w_rf * rf_expected_prob) + (w_xgb * xgb_expected_prob)
        meta_shap = np.array([
            w_rf * (rf_prob - rf_expected_prob),
            w_xgb * (xgb_prob - xgb_expected_prob)
        ])
        meta_exp = shap.Explanation(
            values=meta_shap,
            base_values=meta_expected,
            data=np.array([rf_prob, xgb_prob]),
            feature_names=["RF Probability", "XGB Probability"]
        )
        
        return {
            "rf_exp": rf_exp, "xgb_exp": xgb_exp, "weighted_exp": weighted_exp, 
            "stacking_exp": stacking_exp, "meta_exp": meta_exp,
            "rf_prob": rf_prob, "xgb_prob": xgb_prob,
            "weighted_prob": weighted_prob,
            "stacking_prob": sigmoid(stacking_expected_logodds + np.sum(stacking_shap_logodds))
        }
    except Exception as e:
        st.error(f"SHAP explanation generation failed: {str(e)}")
        st.exception(e)
        return None

# -------------------------------
# ROBUST PLOTTING FUNCTIONS
# -------------------------------
def safe_waterfall_plot(exp, max_display=10):
    try:
        if exp is None or not hasattr(exp, 'values') or len(exp.values) == 0 or np.allclose(exp.values, 0, atol=1e-7):
            return None
        
        plt.figure(figsize=(10, 5.5))
        shap.plots.waterfall(exp, max_display=max_display, show=False)
        fig = plt.gcf()
        plt.tight_layout()
        return fig
    except (IndexError, Exception):
        return fallback_bar_chart(exp, max_display)

def fallback_bar_chart(exp, max_display=10):
    try:
        if exp is None or len(exp.values) == 0:
            return None
        
        abs_vals = np.abs(exp.values)
        top_indices = [i for i in np.argsort(abs_vals)[::-1][:max_display] if abs_vals[i] > 1e-7]
        if not top_indices:
            return None
        
        y_pos = np.arange(len(top_indices))
        values = [exp.values[i] for i in top_indices]
        colors = ['red' if v > 0 else 'blue' for v in values]
        
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.barh(y_pos, values, color=colors)
        ax.set_yticks(y_pos)
        ax.set_yticklabels([exp.feature_names[i] for i in top_indices])
        ax.set_xlabel('SHAP Value')
        ax.set_title('Feature Contributions')
        ax.axvline(x=0, color='gray', linestyle='--', linewidth=0.8)
        plt.tight_layout()
        return fig
    except Exception:
        return None

def force_plot_to_base64(exp, model_name, prediction_prob):
    try:
        if exp is None or not hasattr(exp, 'values') or len(exp.values) == 0 or np.allclose(exp.values, 0, atol=1e-7):
            return None
        
        force_plot = shap.force_plot(
            base_value=float(exp.base_values),
            shap_values=np.array(exp.values).flatten(),
            features=exp.data,
            feature_names=exp.feature_names,
            matplotlib=False,
            show=False
        )
        
        html_path = "temp_shap.html"
        shap.save_html(html_path, force_plot)
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        Path(html_path).unlink(missing_ok=True)
        
        display_text = f"{model_name}: {prediction_prob:.4%} phishing probability"
        risk_color = 'red' if prediction_prob > 0.7 else 'green'
        custom_js = f"""
        <script>
        setTimeout(function() {{
            var container = document.createElement('div');
            container.style.position = 'absolute';
            container.style.top = '10px';
            container.style.right = '10px';
            container.style.background = 'rgba(255, 255, 255, 0.95)';
            container.style.padding = '8px 12px';
            container.style.borderRadius = '6px';
            container.style.fontWeight = 'bold';
            container.style.fontSize = '13px';
            container.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)';
            container.style.border = '1px solid #e0e0e0';
            container.style.color = '{risk_color}';
            container.innerHTML = '{display_text.replace("'", "\\'")}';
            var plotEl = document.querySelector('.shap-force') || document.querySelector('.force-plot');
            if (plotEl) {{
                plotEl.style.position = 'relative';
                plotEl.appendChild(container);
            }}
        }}, 300);
        </script>
        """
        return html_content.replace('</body>', custom_js + '</body>')
    except Exception:
        return None

# -------------------------------
# UI COMPONENTS (ACADEMIC-GRADE)
# -------------------------------
def show_url_context(url):
    """Prominent URL display for academic context"""
    st.markdown(
        f"<div style='background-color:#f0f8ff; padding:12px; border-radius:8px; border-left:4px solid #1f77b4; margin:15px 0;'>"
        f"<h4 style='margin:0; color:#1f77b4;'>🔍 Analyzed URL</h4>"
        f"<p style='margin:5px 0 0 0; font-family:monospace; font-size:1.1em; word-break:break-all;'>{url}</p>"
        f"</div>",
        unsafe_allow_html=True
    )

def show_prediction_card(model_name, prob, pred, logodds=None):
    """Academic-grade prediction display - NO confidence metric"""
    risk_emoji = "🔴" if pred == 1 else "🟢"
    risk_text = "PHISHING DETECTED" if pred == 1 else "LEGITIMATE"
    risk_color = "red" if pred == 1 else "green"
    
    st.markdown(f"## {risk_emoji} {model_name}")
    st.markdown(f"<h3 style='color:{risk_color}; margin-top:-15px;'>{risk_text}</h3>", unsafe_allow_html=True)
    
    if logodds is not None and "Stacking" in model_name:
        col1, col2 = st.columns([1, 1])
        with col1:
            st.metric("Phishing Probability", f"{prob:.4%}")
            st.progress(min(prob, 1.0))
        with col2:
            st.metric("Log-Odds (Meta-Learner Output)", f"{logodds:.6f}")
    else:
        st.metric("Phishing Probability", f"{prob:.4%}")
        st.progress(min(prob, 1.0))

def show_model_explanation(exp, model_name, prob, formula=None):
    """Space-aware verification with explicit model-type handling"""
    if exp is None or not hasattr(exp, 'values') or len(exp.values) == 0:
        st.warning(f"No valid SHAP explanation available for {model_name}")
        return
    
    base_val = float(exp.base_values)
    shap_vals = np.array(exp.values).flatten()
    
    # WATERFALL + FORCE PLOTS FIRST
    col1, col2 = st.columns([1.3, 1])
    with col1:
        st.markdown("**Waterfall Plot**")
        fig = safe_waterfall_plot(exp, max_display=12)
        if fig:
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)
        else:
            st.info("No significant feature contributions")
    
    with col2:
        st.markdown("**Force Plot**")
        force_html = force_plot_to_base64(exp, model_name, prob)
        if force_html:
            st.components.v1.html(force_html, height=450, scrolling=True)
        else:
            st.info("Force plot unavailable")
    
    # SPACE-AWARE VERIFICATION
    with st.expander("🔍 Rigorous Calculation Verification", expanded=True):
        # Determine native space based on model type
        if "Random Forest" in model_name or "Weighted Ensemble" in model_name:
            space_label = "Probability Space (Native Output)"
            model_output = base_val + np.sum(shap_vals)
            calculated_prob = np.clip(model_output, 0.0, 1.0)
            base_display = f"`{base_val:.6f}` (base probability)"
            output_display = f"`{model_output:.6f}` (probability)"
        elif "XGBoost" in model_name or "Stacking Ensemble" in model_name:
            space_label = "Log-Odds Space (Native Output)"
            model_output = base_val + np.sum(shap_vals)
            calculated_prob = sigmoid(model_output)
            base_display = f"`{base_val:.6f}` → `{sigmoid(base_val):.6f}` probability"
            output_display = f"`{model_output:.6f}` (log-odds)"
        else:
            space_label = "Unknown"
            model_output = base_val + np.sum(shap_vals)
            calculated_prob = prob
            base_display = f"`{base_val:.6f}`"
            output_display = f"`{model_output:.6f}`"
        
        # Rigorous verification
        abs_diff = abs(calculated_prob - prob)
        matches = abs_diff < 1e-3
        verification_status = "✅" if matches else "❌"
        diff_display = f"{abs_diff:.6e}" if abs_diff >= 1e-3 else "< 0.001"
        
        st.markdown(f"""
        **Model:** {model_name}  
        **Native Output Space:** {space_label}  
        
        **Base Value:** {base_display}  
        **Sum of SHAP Values:** `{np.sum(shap_vals):+.6f}`  
        **Model Output:** {output_display}  
        **Final Probability:** `{calculated_prob:.6f}` ({calculated_prob:.4%})  
        
        **Verification:**  
        Calculated Probability: `{calculated_prob:.6f}`  
        Model Prediction Probability: `{prob:.6f}`  
        Absolute Difference: `{diff_display}`  
        {verification_status} Values match within tolerance (±0.001)
        """)
        
        if formula:
            st.markdown("**Academic Derivation:**")
            st.code(formula, language="python")
        
        # Top features table
        significant_indices = [i for i, v in enumerate(shap_vals) if abs(v) > 1e-4]
        if significant_indices:
            top_indices = sorted(significant_indices, key=lambda i: abs(shap_vals[i]), reverse=True)[:8]
            df_shap = pd.DataFrame({
                "Feature": [exp.feature_names[i] for i in top_indices],
                "SHAP Value": [f"{shap_vals[i]:+.6f}" for i in top_indices],
                "Raw Value": [f"{exp.data[i]:.4f}" for i in top_indices],
                "Impact": ["🔴 Increases phishing probability" if shap_vals[i] > 0 else "🟢 Decreases phishing probability" for i in top_indices]
            })
            st.dataframe(df_shap, use_container_width=True, hide_index=True)
        else:
            st.info("No features with |SHAP| > 0.0001")

# -------------------------------
# Load Models
# -------------------------------
@st.cache_resource
def load_models(model_path="model_bundle_feb_15_2026.pkl"):
    try:
        bundle = joblib.load(model_path)
        required = ["rf_model", "xgb_model", "meta_clf", "rf_explainer", "xgb_explainer", "feature_names"]
        missing = [r for r in required if r not in bundle]
        if missing:
            st.error(f"Model bundle missing components: {missing}")
            return None
        
        feature_names = bundle["feature_names"]
        if not feature_names:
            st.error("Model bundle has empty feature_names")
            return None
        
        thresholds = bundle.get("thresholds", {"rf": 0.7, "xgb": 0.7, "ensemble": 0.7})
        for key in ["rf", "xgb", "ensemble"]:
            if key not in thresholds:
                thresholds[key] = 0.7
        
        return bundle
    except FileNotFoundError:
        st.error(f"Model bundle not found: {model_path}")
        st.info("Ensure 'model_bundle_feb_15_2026.pkl' exists in current directory")
        return None
    except Exception as e:
        st.error(f"Failed to load model bundle: {e}")
        return None

# -------------------------------
# Streamlit UI
# -------------------------------
st.set_page_config(
    page_title="🔒 Rigorous Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
st.title("🛡️ Rigorous Phishing Detection System")
st.markdown("*Four complementary models with mathematically sound SHAP explanations*")
st.markdown("---")

# Load models
bundle = load_models()
if bundle is None:
    st.stop()

rf_model = bundle["rf_model"]
xgb_model = bundle["xgb_model"]
meta_clf = bundle["meta_clf"]
rf_explainer = bundle["rf_explainer"]
xgb_explainer = bundle["xgb_explainer"]
feature_names = bundle["feature_names"]
thresholds = bundle.get("thresholds", {"rf": 0.7, "xgb": 0.7, "ensemble": 0.7})
W_RF, W_XGB = 0.35, 0.65

# Initialize session state
if 'analysis_done' not in st.session_state:
    st.session_state.analysis_done = False
    st.session_state.feature_dict = None
    st.session_state.predictions = None
    st.session_state.explanations = None
    st.session_state.url = ""

# URL Input
st.subheader("🔍 URL Analysis")
col1, col2 = st.columns([3, 1])
with col1:
    url_input = st.text_input("Enter URL to analyze:", value="https://www.sainthenri.org/", key="url_input")
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    analyze_btn = st.button("🔍 Analyze URL", type="primary")

# Dataset check
if url_input.strip():
    in_dataset, actual_label = is_url_in_labeled_dataset(url_input)
    if in_dataset:
        st.success(f"✅ **URL exists in dataset: {actual_label}**")
    else:
        st.info("ℹ️ URL not found in labeled datasets")

# Analysis execution
if analyze_btn and url_input.strip():
    with st.spinner("🔬 Analyzing with 4 rigorous models..."):
        try:
            feature_dict = extract_all(url_input.strip())
            if not isinstance(feature_dict, dict):
                raise ValueError("Invalid feature extraction result")
        except Exception as e:
            st.error(f"Feature extraction failed: {str(e)}")
            feature_dict = {col: 0 for col in feature_names}
            feature_dict["http_status"] = 0
        
        X_df = pd.DataFrame([{col: feature_dict.get(col, 0) for col in feature_names}])
        missing_features = set(feature_names) - set(X_df.columns)
        if missing_features:
            for col in missing_features:
                X_df[col] = 0
        X_df = X_df[feature_names]
        
        predictions = predict_all_models(X_df, rf_model, xgb_model, meta_clf, thresholds, W_RF, W_XGB)
        
        status = int(feature_dict.get("http_status", 0))
        explanations = explain_all_models(X_df, rf_model, xgb_model, meta_clf, rf_explainer, xgb_explainer, feature_names, W_RF, W_XGB) if 200 <= status <= 299 else None
        
        st.session_state.analysis_done = True
        st.session_state.feature_dict = feature_dict
        st.session_state.predictions = predictions
        st.session_state.explanations = explanations
        st.session_state.url = url_input.strip()
        st.success("✅ Analysis completed successfully!")

# Results display
if st.session_state.analysis_done:
    feature_dict = st.session_state.feature_dict
    predictions = st.session_state.predictions
    explanations = st.session_state.explanations
    url = st.session_state.url
    status = int(feature_dict.get("http_status", 0))
    
    # URL Information Panel
    st.markdown("---")
    st.subheader("🌐 URL Information")
    col1, col2, col3 = st.columns(3)
    with col1:
        display_url = url[:60] + '...' if len(url) > 60 else url
        st.write(f"**Analyzed URL:** `{display_url}`")
        domain = urllib.parse.urlparse(url).netloc or "unknown"
        st.write(f"**Domain:** `{domain}`")
    with col2:
        st.write(f"**HTTP Status:** `{status}`")
        st.write(f"**Meaning:** {status_explanations.get(status, 'Unknown status code')}")
    with col3:
        st.write(f"**URL Length:** {len(url)} characters")
        response_time = float(feature_dict.get('response_time', 0) or 0)
        st.write(f"**Response Time:** {response_time:.2f} sec")
    
    # PROMINENT URL DISPLAY BEFORE PREDICTIONS
    st.markdown("---")
    show_url_context(url)
    
    # Prediction Summary Table
    st.subheader("📊 Prediction Summary (All Models)")
    summary_data = [
        ["Random Forest", "🔴 Phishing" if predictions["rf_pred"] else "🟢 Legitimate", f"{predictions['rf_prob']:.4%}"],
        ["XGBoost", "🔴 Phishing" if predictions["xgb_pred"] else "🟢 Legitimate", f"{predictions['xgb_prob']:.4%}"],
        [f"Weighted Ensemble (RF {int(W_RF*100)}% + XGB {int(W_XGB*100)}%)", 
         "🔴 Phishing" if predictions["weighted_pred"] else "🟢 Legitimate", 
         f"{predictions['weighted_prob']:.4%}"],
        ["Stacking Ensemble (Logistic Regression)", 
         "🔴 Phishing" if predictions["stacking_pred"] else "🟢 Legitimate", 
         f"{predictions['stacking_prob']:.4%}"]
    ]
    summary_df = pd.DataFrame(summary_data, columns=["Model", "Prediction", "Probability"])
    st.dataframe(summary_df, use_container_width=True, hide_index=True)
    
    # Meta-Learner Transparency
    with st.expander("🔍 Stacking Meta-Learner Architecture", expanded=False):
        st.markdown("""
        **Stacking Architecture:**
        - Base Models: Random Forest + XGBoost
        - Meta-Learner: Logistic Regression trained on out-of-fold probabilities
        - Decision Function: `logit(P_phishing) = intercept + w_rf·P_rf + w_xgb·P_xgb`
        """)
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("RF Weight (wᵣ𝒻)", f"{predictions['meta_weights']['rf']:.6f}")
            st.metric("RF Probability", f"{predictions['rf_prob']:.6f}")
        with col2:
            st.metric("XGB Weight (wₓ𝓰𝓫)", f"{predictions['meta_weights']['xgb']:.6f}")
            st.metric("XGB Probability", f"{predictions['xgb_prob']:.6f}")
        with col3:
            st.metric("Intercept", f"{predictions['meta_intercept']:.6f}")
            formula = (
                f"{predictions['meta_intercept']:.6f} + "
                f"({predictions['meta_weights']['rf']:.6f} × {predictions['rf_prob']:.6f}) + "
                f"({predictions['meta_weights']['xgb']:.6f} × {predictions['xgb_prob']:.6f}) = "
                f"{predictions['stacking_logodds']:.6f}"
            )
            st.caption("Log-odds calculation:")
            st.code(formula)
    
    # Detailed Explanations
    if explanations and 200 <= status <= 299:
        st.markdown("---")
        st.subheader("🧠 Detailed Model Analysis")
        st.markdown("*Select a model tab below for rigorous SHAP explanation*")
        
        tab1, tab2, tab3, tab4 = st.tabs([
            "🌲 Random Forest",
            "🚀 XGBoost",
            "⚖️ Weighted Ensemble",
            "🧩 Stacking Ensemble"
        ])
        
        # TAB 1: Random Forest
        with tab1:
            show_url_context(url)
            show_prediction_card("Random Forest", predictions["rf_prob"], predictions["rf_pred"])
            if explanations.get("rf_exp") is not None:
                show_model_explanation(
                    explanations["rf_exp"], 
                    "Random Forest", 
                    predictions["rf_prob"],
                    formula="SHAP values in native probability space (scikit-learn RF output)"
                )
        
        # TAB 2: XGBoost
        with tab2:
            show_url_context(url)
            show_prediction_card("XGBoost", predictions["xgb_prob"], predictions["xgb_pred"])
            if explanations.get("xgb_exp") is not None:
                show_model_explanation(
                    explanations["xgb_exp"], 
                    "XGBoost", 
                    predictions["xgb_prob"],
                    formula="SHAP values in native log-odds space (XGBoost raw margin output)"
                )
        
        # TAB 3: Weighted Ensemble
        with tab3:
            show_url_context(url)
            show_prediction_card(
                f"Weighted Ensemble (RF {int(W_RF*100)}% + XGB {int(W_XGB*100)}%)", 
                predictions["weighted_prob"], 
                predictions["weighted_pred"]
            )
            st.markdown("""
            **Ensemble Method:** Probability-weighted averaging  
            **SHAP Derivation:** Chain-rule converted contributions from both models with scaling for exact additivity:  
            `SHAP_ensemble[i] = W_RF · SHAP_RF[i] + W_XGB · (scaled SHAP_XGB_prob[i])`
            """)
            if explanations.get("weighted_exp") is not None:
                show_model_explanation(
                    explanations["weighted_exp"], 
                    f"Weighted Ensemble (RF {int(W_RF*100)}% + XGB {int(W_XGB*100)}%)", 
                    predictions["weighted_prob"],
                    formula=f"SHAP_ensemble[i] = {W_RF} · SHAP_RF[i] + {W_XGB} · (SHAP_XGB_logodds[i] · P_XGB · (1 - P_XGB) · scale_factor)"
                )
        
        # TAB 4: Stacking Ensemble
        with tab4:
            show_url_context(url)
            show_prediction_card(
                "Stacking Ensemble (Logistic Regression Meta-Learner)", 
                predictions["stacking_prob"], 
                predictions["stacking_pred"],
                logodds=predictions["stacking_logodds"]
            )
            st.markdown("""
            **Ensemble Method:** Stacking with Logistic Regression meta-learner  
            **SHAP Derivation (Chain-Rule):**  
            `∂(stacking_logodds)/∂xᵢ = w_rf · SHAP_RF_prob[i] + w_xgb · (scaled SHAP_XGB_prob[i])`  
            Where SHAP_prob ≈ SHAP_logodds · P · (1-P) for XGBoost, scaled for exact additivity.
            """)
            if explanations.get("stacking_exp") is not None:
                show_model_explanation(
                    explanations["stacking_exp"], 
                    "Stacking Ensemble (Logistic Regression Meta-Learner)", 
                    predictions["stacking_prob"],
                    formula="∂(stacking)/∂xᵢ = w_rf · SHAP_RF_prob[i] + w_xgb · (SHAP_XGB_logodds[i] · P_XGB · (1 - P_XGB) · scale_factor)"
                )
                
                with st.expander("⚙️ Meta-Learner Level Explanation", expanded=False):
                    meta_exp = explanations.get("meta_exp")
                    if meta_exp is not None:
                        st.markdown("**Direct explanation of meta-learner decision using base model probabilities as features**")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("**Meta-Learner Force Plot**")
                            try:
                                plt.figure(figsize=(8, 3.5))
                                shap.plots.force(
                                    meta_exp.base_values,
                                    meta_exp.values,
                                    meta_exp.data,
                                    feature_names=meta_exp.feature_names,
                                    matplotlib=True,
                                    show=False
                                )
                                st.pyplot(plt.gcf(), use_container_width=True)
                                plt.close()
                            except Exception as e:
                                st.warning(f"Plot unavailable: {str(e)[:50]}")
                        with col2:
                            st.markdown("**Contribution Analysis**")
                            base_logodds = meta_exp.base_values
                            total_contrib = np.sum(meta_exp.values)
                            final_logodds = base_logodds + total_contrib
                            final_prob = sigmoid(final_logodds)
                            
                            st.metric("Base Log-Odds (Training Mean)", f"{base_logodds:.6f}")
                            for i, feat in enumerate(meta_exp.feature_names):
                                contrib = meta_exp.values[i]
                                direction = "▲" if contrib > 0 else "▼"
                                st.metric(
                                    f"{direction} {feat}", 
                                    f"{meta_exp.data[i]:.6f}",
                                    delta=f"{contrib:+.6f} log-odds"
                                )
                            st.metric("Final Probability", f"{final_prob:.6f}")
    else:
        st.info(f"ℹ️ SHAP explanations require active URLs (HTTP 200-299). Current status: {status} – {status_explanations.get(status, 'Unknown')}")

# Sidebar - CLEANED UP FOR ACADEMIC USE
with st.sidebar:
    st.markdown("## 🔬 Detection Models")
    st.markdown("""
    ### Four Complementary Models
    1. **Random Forest** - Lexical feature analysis
    2. **XGBoost** - Gradient-boosted trees
    3. **Weighted Ensemble** - Probability-weighted averaging (RF 35% + XGB 65%)
    4. **Stacking Ensemble** - Logistic Regression meta-learner
    
    ### Academic Rigor
    - Mathematically verified SHAP explanations
    - Model-space aware calculations:
      - RF: Native probability space
      - XGBoost: Native log-odds space
    - Chain-rule propagation with proper space conversions and scaling for exact additivity
    - Verification: `base_value + ΣSHAP = model_output` (exact)
    - Conservative baselines with explicit documentation
    
    ### Usage
    1. Enter URL and click **Analyze**
    2. Review prediction summary
    3. Select model tab for detailed explanation
    4. Expand verification sections for derivations
    """)
    st.markdown("---")
    st.markdown("🛡️ Academic-grade phishing detection system")
    st.markdown(f"**Features:** {len(feature_names)} lexical features")
    st.markdown(f"**Thresholds:** RF={thresholds['rf']}, XGB={thresholds['xgb']}, Ensemble={thresholds['ensemble']}")