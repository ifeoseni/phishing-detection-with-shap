# feature_extractor_live.py
import re
import math
import ssl
import socket
import time
import cloudscraper
import whois
import tldextract
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import logging
import dns.resolver

# ------------------------------------------------------------------
# Setup Logging
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("feature_extraction.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
SUSPICIOUS_TLDS = ['biz', 'buzz', 'cf', 'club', 'cn', 'com', 'ga', 'gq', 'host', 'icu', 'info', 'live', 'ml', 'name', 'net', 'online', 'org', 'ru', 'tk', 'top', 'us', 'wang', 'ws', 'xyz']
SHORTENING_SERVICES = {
    '0.gp', '02faq.com', '0a.sk', '101.gg', '12ne.ws', '17mimei.club', '1drv.ms', '1ea.ir', '1kh.de', '1o2.ir', '1shop.io', '1u.fi', '1un.fr', '1url.cz', '2.gp', '2.ht', '2.ly', '2doc.net', '2fear.com', '2kgam.es', '2link.cc', '2nu.gs', '2pl.us', '2u.lc', '2u.pw', '2wsb.tv', '3.cn', '3.ly', '301.link', '3le.ru', '4.gp', '4.ly', '49rs.co', '4sq.com', '5.gp', '52.nu', '53eig.ht', '5du.pl', '5w.fit', '6.gp', '6.ly', '69run.fun', '6g6.eu', '7.ly', '707.su', '71a.xyz', '7news.link', '7ny.tv', '7oi.de', '8.ly', '89q.sk', '8fig.me', '92url.com', '985.so', '98pro.cc', '9mp.com', '9splay.store', 'a.189.cn', 'a.co', 'a360.co', 'aarp.info', 'ab.co', 'abc.li', 'abc11.tv', 'abc13.co', 'abc7.la', 'abc7.ws', 'abc7ne.ws', 'abcn.ws', 'abe.ma', 'abelinc.me', 'abnb.me', 'abr.ai', 'abre.ai', 'accntu.re', 'accu.ps', 'acer.co', 'acer.link', 'aces.mp', 'acortar.link', 'act.gp', 'acus.org', 'adaymag.co', 'adb.ug', 'adbl.co', 'adf.ly', 'adfoc.us', 'adm.to', 'adobe.ly', 'adol.us', 'adweek.it', 'aet.na', 'agrd.io', 'ai6.net', 'aje.io', 'aka.ms', 'al.st', 'alexa.design', 'alli.pub', 'alnk.to', 'alpha.camp', 'alphab.gr', 'alturl.com', 'amays.im', 'amba.to', 'amc.film', 'amex.co', 'ampr.gs', 'amrep.org', 'amz.run', 'amzn.com', 'amzn.pw', 'amzn.to', 'ana.ms', 'anch.co', 'ancstry.me', 'andauth.co', 'anon.to', 'anyimage.io', 'aol.it', 'aon.io', 'apne.ws', 'app.philz.us', 'apple.co', 'apple.news', 'aptg.tw', 'arah.in', 'arc.ht', 'arkinv.st', 'asics.tv', 'asin.cc', 'asq.kr', 'asus.click', 'at.vibe.com', 'atm.tk', 'atmilb.com', 'atmlb.com', 'atres.red', 'autode.sk', 'avlne.ws', 'avlr.co', 'avydn.co', 'axios.link', 'axoni.us', 'ay.gy', 'azc.cc', 'b-gat.es', 'b.link', 'b.mw', 'b23.ru', 'b23.tv', 'b2n.ir', 'baratun.de', 'bayareane.ws', 'bbc.in', 'bbva.info', 'bc.vc', 'bca.id', 'bcene.ws', 'bcove.video', 'bcsite.io', 'bddy.me', 'beats.is', 'benqurl.biz', 'beth.games', 'bfpne.ws', 'bg4.me', 'bhpho.to', 'bigcc.cc', 'bigfi.sh', 'biggo.tw', 'biibly.com', 'binged.it', 'bit.ly', 'bitly.com', 'bitly.is', 'bitly.lc', 'bityl.co', 'bl.ink', 'blap.net', 'blbrd.cm', 'blck.by', 'blizz.ly', 'bloom.bg', 'blstg.news', 'blur.by', 'bmai.cc', 'bnds.in', 'bnetwhk.com', 'bo.st', 'boa.la', 'boile.rs', 'bom.so', 'bonap.it', 'booki.ng', 'bookstw.link', 'bose.life', 'boston25.com', 'bp.cool', 'br4.in', 'bravo.ly', 'bridge.dev', 'brief.ly', 'brook.gs', 'browser.to', 'bst.bz', 'bstk.me', 'btm.li', 'btwrdn.com', 'budurl.com', 'buff.ly', 'bung.ie', 'bwnews.pr', 'by2.io', 'bytl.fr', 'bzfd.it', 'bzh.me', 'c11.kr', 'c87.to', 'cadill.ac', 'can.al', 'canon.us', 'capital.one', 'capitalfm.co', 'captl1.co', 'careem.me', 'caro.sl', 'cart.mn', 'casio.link', 'cathaybk.tw', 'cathaysec.tw', 'cb.com', 'cbj.co', 'cbsloc.al', 'cbsn.ws', 'cbt.gg', 'cc.cc', 'cdl.booksy.com', 'cfl.re', 'chip.tl', 'chl.li', 'chn.ge', 'chn.lk', 'chng.it', 'chts.tw', 'chzb.gr', 'cin.ci', 'cindora.club', 'circle.ci', 'cirk.me', 'cisn.co', 'citi.asia', 'cjky.it', 'ckbe.at', 'cl.ly', 'clarobr.co', 'clc.am', 'clc.to', 'clck.ru', 'cle.clinic', 'cli.re', 'clickmeter.com', 'clicky.me', 'clr.tax', 'clvr.rocks', 'cmon.co', 'cmu.is', 'cmy.tw', 'cna.asia', 'cnb.cx', 'cnet.co', 'cnfl.io', 'cnn.it', 'cnnmon.ie', 'cnvrge.co', 'cockroa.ch', 'comca.st', 'conta.cc', 'cookcenter.info', 'coop.uk', 'cort.as', 'coupa.ng', 'cplink.co', 'cr8.lv', 'crackm.ag', 'crdrv.co', 'credicard.biz', 'crwd.fr', 'crwd.in', 'crwdstr.ke', 'cs.co', 'csmo.us', 'cstu.io', 'ctbc.tw', 'ctfl.io', 'cultm.ac', 'cup.org', 'cut.lu', 'cut.pe', 'cutt.ly', 'cvent.me', 'cvs.co', 'cyb.ec', 'cybr.rocks', 'd-sh.io', 'da.gd', 'dai.ly', 'dailym.ai', 'dainik-b.in', 'datayi.cn', 'davidbombal.wiki', 'db.tt', 'dbricks.co', 'dcps.co', 'dd.ma', 'deb.li', 'dee.pl', 'deli.bz', 'dell.to', 'deloi.tt', 'dems.me', 'dhk.gg', 'di.sn', 'dibb.me', 'dis.gd', 'dis.tl', 'discord.gg', 'discvr.co', 'disq.us', 'dive.pub', 'djex.co', 'dk.rog.gg', 'dkng.co', 'dky.bz', 'dl.gl', 'dld.bz', 'dlsh.it', 'dlvr.it', 'dmdi.pl', 'dmreg.co', 'do.co', 'dockr.ly', 'dopice.sk', 'dpmd.ai', 'dpo.st', 'dssurl.com', 'dtdg.co', 'dtsx.io', 'dub.sh', 'dv.gd', 'dvrv.ai', 'dw.com', 'dwz.tax', 'dxc.to', 'dy.fi', 'dy.si', 'e.lilly', 'e.vg', 'ebay.to', 'econ.st', 'ed.gr', 'edin.ac', 'edu.nl', 'eepurl.com', 'efshop.tw', 'ela.st', 'elle.re', 'ellemag.co', 'embt.co', 'emirat.es', 'engt.co', 'enshom.link', 'entm.ag', 'envs.sh', 'epochtim.es', 'ept.ms', 'eqix.it', 'es.pn', 'es.rog.gg', 'escape.to', 'esl.gg', 'eslite.me', 'esqr.co', 'esun.co', 'etoro.tw', 'etp.tw', 'etsy.me', 'everri.ch', 'exe.io', 'exitl.ag', 'ezstat.ru', 'f1.com', 'f5yo.com', 'fa.by', 'fal.cn', 'fam.ag', 'fandan.co', 'fandom.link', 'fandw.me', 'faras.link', 'faturl.com', 'fav.me', 'fave.co', 'fb.me', 'fb.watch', 'fbstw.link', 'fce.gg', 'fetnet.tw', 'fevo.me', 'ff.im', 'fifa.fans', 'firsturl.de', 'firsturl.net', 'flic.kr', 'flip.it', 'flomuz.io', 'flq.us', 'fltr.ai', 'flx.to', 'fmurl.cc', 'fn.gg', 'fnb.lc', 'foodtv.com', 'fooji.info', 'ford.to', 'forms.gle', 'forr.com', 'found.ee', 'fox.tv', 'fr.rog.gg', 'frdm.mobi', 'fstrk.cc', 'ftnt.net', 'fumacrom.com', 'fvrr.co', 'fwme.eu', 'fxn.ws', 'g-web.in', 'g.asia', 'g.co', 'g.page', 'ga.co', 'galien.org', 'gandi.link', 'garyvee.com', 'gaw.kr', 'gbod.org', 'gbpg.net', 'gbte.tech', 'gclnk.com', 'gdurl.com', 'gek.link', 'gen.cat', 'geni.us', 'genie.co.kr', 'getf.ly', 'geti.in', 'gfuel.ly', 'gh.io', 'ghkp.us', 'gi.lt', 'gigaz.in', 'git.io', 'github.co', 'gizmo.do', 'gjk.id', 'glbe.co', 'glblctzn.co', 'glblctzn.me', 'gldr.co', 'glmr.co', 'glo.bo', 'gma.abc', 'gmj.tw', 'go-link.ru', 'go.aws', 'go.btwrdn.co', 'go.cwtv.com', 'go.dbs.com', 'go.edh.tw', 'go.gcash.com', 'go.hny.co', 'go.id.me', 'go.intel-academy.com', 'go.intigriti.com', 'go.jc.fm', 'go.lamotte.fr', 'go.lu-h.de', 'go.ly', 'go.nasa.gov', 'go.nowth.is', 'go.osu.edu', 'go.qb.by', 'go.rebel.pl', 'go.shell.com', 'go.shr.lc', 'go.sony.tw', 'go.tinder.com', 'go.usa.gov', 'go.ustwo.games', 'go.vic.gov.au', 'godrk.de', 'gofund.me', 'gomomento.co', 'goo-gl.me', 'goo.by', 'goo.gl', 'goo.gle', 'goo.su', 'goolink.cc', 'goolnk.com', 'gosm.link', 'got.cr', 'got.to', 'gov.tw', 'gowat.ch', 'gph.to', 'gq.mn', 'gr.pn', 'grb.to', 'grdt.ai', 'grm.my', 'grnh.se', 'gtly.ink', 'gtly.to', 'gtne.ws', 'gtnr.it', 'gym.sh', 'haa.su', 'han.gl', 'hashi.co', 'hbaz.co', 'hbom.ax', 'her.is', 'herff.ly', 'hf.co', 'hi.kktv.to', 'hi.sat.cool', 'hi.switchy.io', 'hicider.com', 'hideout.cc', 'hill.cm', 'histori.ca', 'hmt.ai', 'hnsl.mn', 'homes.jp', 'hp.care', 'hpe.to', 'hrbl.me', 'href.li', 'ht.ly', 'htgb.co', 'htl.li', 'htn.to', 'httpslink.com', 'hubs.la', 'hubs.li', 'hubs.ly', 'huffp.st', 'hulu.tv', 'huma.na', 'hyperurl.co', 'hyperx.gg', 'i-d.co', 'i.coscup.org', 'i.mtr.cool', 'ibb.co', 'ibf.tw', 'ibit.ly', 'ibm.biz', 'ibm.co', 'ic9.in', 'icit.fr', 'icks.ro', 'iea.li', 'ifix.gd', 'ift.tt', 'iherb.co', 'ihr.fm', 'ii1.su', 'iii.im', 'iiil.io', 'il.rog.gg', 'ilang.in', 'illin.is', 'iln.io', 'ilnk.io', 'imdb.to', 'ind.pn', 'indeedhi.re', 'indy.st', 'infy.com', 'inlnk.ru', 'insd.io', 'insig.ht', 'instagr.am', 'intel.ly', 'interc.pt', 'intuit.me', 'invent.ge', 'inx.lv', 'ionos.ly', 'ipgrabber.ru', 'ipgraber.ru', 'iplogger.co', 'iplogger.com', 'iplogger.info', 'iplogger.org', 'iplogger.ru', 'iplwin.us', 'iqiyi.cn', 'irng.ca', 'is.gd', 'isw.pub', 'itsh.bo', 'itvty.com', 'ity.im', 'ix.sk', 'j.gs', 'j.mp', 'ja.cat', 'ja.ma', 'jb.gg', 'jcp.is', 'jkf.lv', 'jnfusa.org', 'joo.gl', 'jp.rog.gg', 'jpeg.ly', 'jsparty.fm', 'k-p.li', 'kas.pr', 'kask.us', 'katzr.net', 'kbank.co', 'kck.st', 'kf.org', 'kfrc.co', 'kg.games', 'kgs.link', 'kham.tw', 'kings.tn', 'kkc.tech', 'kkday.me', 'kkne.ws', 'kko.to', 'kkstre.am', 'kl.ik.my', 'klck.me', 'kli.cx', 'klmf.ly', 'ko.gl', 'kortlink.dk', 'kotl.in', 'kp.org', 'kpmg.ch', 'krazy.la', 'kuku.lu', 'kurl.ru', 'kutt.it', 'ky77.link', 'l.linklyhq.com', 'l.prageru.com', 'l8r.it', 'laco.st', 'lam.bo', 'lat.ms', 'latingram.my', 'lativ.tw', 'lbtw.tw', 'lc.chat', 'lc.cx', 'learn.to', 'lego.build', 'lemde.fr', 'letsharu.cc', 'lft.to', 'lih.kg', 'lihi.biz', 'lihi.cc', 'lihi.one', 'lihi.pro', 'lihi.tv', 'lihi.vip', 'lihi1.cc', 'lihi1.com', 'lihi1.me', 'lihi2.cc', 'lihi2.com', 'lihi2.me', 'lihi3.cc', 'lihi3.com', 'lihi3.me', 'lihipro.com', 'lihivip.com', 'liip.to', 'lin.ee', 'lin0.de', 'link.ac', 'link.infini.fr', 'link.tubi.tv', 'linkbun.com', 'linkd.in', 'linkjust.com', 'linko.page', 'linkopener.co', 'links2.me', 'linkshare.pro', 'linkye.net', 'livemu.sc', 'livestre.am', 'llk.dk', 'llo.to', 'lmg.gg', 'lmt.co', 'lmy.de', 'lnk.bz', 'lnk.direct', 'lnk.do', 'lnk.sk', 'lnkd.in', 'lnkiy.com', 'lnkiy.in', 'lnky.jp', 'lnnk.in', 'lnv.gy', 'lohud.us', 'lonerwolf.co', 'loom.ly', 'low.es', 'lprk.co', 'lru.jp', 'lsdl.es', 'lstu.fr', 'lt27.de', 'lttr.ai', 'ludia.gg', 'luminary.link', 'lurl.cc', 'lyksoomu.com', 'lzd.co', 'm.me', 'm.tb.cn', 'm101.org', 'm1p.fr', 'maac.io', 'maga.lu', 'man.ac.uk', 'many.at', 'maper.info', 'mapfan.to', 'mayocl.in', 'mbapp.io', 'mbayaq.co', 'mcafee.ly', 'mcd.to', 'mcgam.es', 'mck.co', 'mcys.co', 'me.sv', 'me2.kr', 'meck.co', 'meetu.ps', 'merky.de', 'metamark.net', 'mgnet.me', 'mgstn.ly', 'michmed.org', 'migre.me', 'minify.link', 'minilink.io', 'mitsha.re', 'mklnd.com', 'mm.rog.gg', 'mmz.li', 'mney.co', 'mng.bz', 'mnge.it', 'mnot.es', 'mo.ma', 'momo.dm', 'monster.cat', 'moo.im', 'moovit.me', 'mork.ro', 'mou.sr', 'mpl.pm', 'mrte.ch', 'mrx.cl', 'ms.spr.ly', 'msft.it', 'msi.gm', 'mstr.cl', 'mttr.io', 'mub.me', 'munbyn.biz', 'mvmtwatch.co', 'my.mtr.cool', 'mybmw.tw', 'myglamm.in', 'mylt.tv', 'mypoya.com', 'myppt.cc', 'mysp.ac', 'myumi.ch', 'myurls.ca', 'mz.cm', 'mzl.la', 'n.opn.tl', 'n.pr', 'n9.cl', 'name.ly', 'nature.ly', 'nav.cx', 'naver.me', 'nbc4dc.com', 'nbcbay.com', 'nbcchi.com', 'nbcct.co', 'nbcnews.to', 'nbzp.cz', 'nchcnh.info', 'nej.md', 'neti.cc', 'netm.ag', 'nflx.it', 'ngrid.com', 'njersy.co', 'nkbp.jp', 'nkf.re', 'nmrk.re', 'nnn.is', 'nnna.ru', 'nokia.ly', 'notlong.com', 'nr.tn', 'nswroads.work', 'ntap.com', 'ntck.co', 'ntn.so', 'ntuc.co', 'nus.edu', 'nvda.ws', 'nwppr.co', 'nwsdy.li', 'nxb.tw', 'nxdr.co', 'nycu.to', 'nydn.us', 'nyer.cm', 'nyp.st', 'nyr.kr', 'nyti.ms', 'o.vg', 'oal.lu', 'obank.tw', 'ock.cn', 'ocul.us', 'oe.cd', 'ofcour.se', 'offerup.co', 'offf.to', 'offs.ec', 'okt.to', 'omni.ag', 'on.bcg.com', 'on.bp.com', 'on.fb.me', 'on.ft.com', 'on.louisvuitton.com', 'on.mktw.net', 'on.natgeo.com', 'on.nba.com', 'on.ny.gov', 'on.nyc.gov', 'on.nypl.org', 'on.tcs.com', 'on.wsj.com', 'on9news.tv', 'onelink.to', 'onepl.us', 'onforb.es', 'onion.com', 'onx.la', 'oow.pw', 'opr.as', 'opr.news', 'optimize.ly', 'oran.ge', 'orlo.uk', 'osdb.link', 'oshko.sh', 'ouo.io', 'ouo.press', 'ourl.co', 'ourl.in', 'ourl.tw', 'outschooler.me', 'ovh.to', 'ow.ly', 'owl.li', 'owy.mn', 'oxelt.gl', 'oxf.am', 'oyn.at', 'p.asia', 'p.dw.com', 'p1r.es', 'p4k.in', 'pa.ag', 'packt.link', 'pag.la', 'pchome.link', 'pck.tv', 'pdora.co', 'pdxint.at', 'pe.ga', 'pens.pe', 'peoplem.ag', 'pepsi.co', 'pesc.pw', 'petrobr.as', 'pew.org', 'pewrsr.ch', 'pg3d.app', 'pgat.us', 'pgrs.in', 'philips.to', 'piee.pw', 'pin.it', 'pipr.es', 'pj.pizza', 'pl.kotl.in', 'pldthome.info', 'plu.sh', 'pnsne.ws', 'pod.fo', 'poie.ma', 'poie.ma', 'pojonews.co', 'politi.co', 'popm.ch', 'posh.mk', 'pplx.ai', 'ppt.cc', 'ppurl.io', 'pr.tn', 'prbly.us', 'prdct.school', 'preml.ge', 'prf.hn', 'prgress.co', 'prn.to', 'propub.li', 'pros.is', 'psce.pw', 'pse.is', 'psee.io', 'pt.rog.gg', 'ptix.co', 'puext.in', 'purdue.university', 'purefla.sh', 'puri.na', 'pwc.to', 'pxgo.net', 'pxu.co', 'pzdls.co', 'q.gs', 'qnap.to', 'qptr.ru', 'qr.ae', 'qr.net', 'qrco.de', 'qrs.ly', 'qvc.co', 'r-7.co', 'r.zecz.ec', 'rb.gy', 'rbl.ms', 'rblx.co', 'rch.lt', 'rd.gt', 'rdbl.co', 'rdcrss.org', 'rdcu.be', 'read.bi', 'readhacker.news', 'rebelne.ws', 'rebrand.ly', 'reconis.co', 'red.ht', 'redaz.in', 'redd.it', 'redir.ec', 'redir.is', 'redsto.ne', 'ref.trade.re', 'referer.us', 'refini.tv', 'regmovi.es', 'reline.cc', 'relink.asia', 'rem.ax', 'renew.ge', 'replug.link', 'rethinktw.cc', 'reurl.cc', 'reut.rs', 'rev.cm', 'revr.ec', 'rfr.bz', 'ringcentr.al', 'riot.com', 'rip.city', 'risu.io', 'ritea.id', 'rizy.ir', 'rlu.ru', 'rly.pt', 'rnm.me', 'ro.blox.com', 'rog.gg', 'roge.rs', 'rol.st', 'rotf.lol', 'rozhl.as', 'rpf.io', 'rptl.io', 'rsc.li', 'rsh.md', 'rtvote.com', 'ru.rog.gg', 'rushgiving.com', 'rushtix.co', 'rvtd.io', 'rvwd.co', 'rwl.io', 'ryml.me', 'rzr.to', 's.accupass.com', 's.coop', 's.g123.jp', 's.id', 's.mj.run', 's.ul.com', 's.uniqlo.com', 's.wikicharlie.cl', 's04.de', 's3vip.tw', 'saf.li', 'safelinking.net', 'safl.it', 'sail.to', 'samcart.me', 'sbird.co', 'sbux.co', 'sbux.jp', 'sc.mp', 'sc.org', 'sched.co', 'sck.io', 'scr.bi', 'scrb.ly', 'scuf.co', 'sdpbne.ws', 'sdu.sk', 'sdut.us', 'se.rog.gg', 'seagate.media', 'sealed.in', 'seedsta.rs', 'seiu.co', 'sejr.nl', 'selnd.com', 'seq.vc', 'sf3c.tw', 'sfca.re', 'sfcne.ws', 'sforce.co', 'sfty.io', 'sgq.io', 'shar.as', 'shiny.link', 'shln.me', 'sho.pe', 'shope.ee', 'shorl.com', 'short.gy', 'shorten.asia', 'shorturl.ae', 'shorturl.asia', 'shorturl.at', 'shorturl.com', 'shorturl.gg', 'shp.ee', 'shrtm.nu', 'sht.moe', 'shutr.bz', 'sie.ag', 'simp.ly', 'sina.lt', 'sincere.ly', 'sinourl.tw', 'sinyi.biz', 'sinyi.in', 'siriusxm.us', 'siteco.re', 'skimmth.is', 'skl.sh', 'skrat.it', 'skyurl.cc', 'slidesha.re', 'small.cat', 'smart.link', 'smarturl.it', 'smashed.by', 'smlk.es', 'smonty.co', 'smsb.co', 'smsng.news', 'smsng.us', 'smtvj.com', 'smu.gs', 'snd.sc', 'sndn.link', 'snip.link', 'snip.ly', 'snyk.co', 'so.arte', 'soc.cr', 'soch.us', 'social.ora.cl', 'socx.in', 'sokrati.ru', 'solsn.se', 'sou.nu', 'sourl.cn', 'sovrn.co', 'spcne.ws', 'spgrp.sg', 'spigen.co', 'split.to', 'splk.it', 'spoti.fi', 'spotify.link', 'spr.ly', 'spr.tn', 'sprtsnt.ca', 'sqex.to', 'sqrx.io', 'squ.re', 'srnk.us', 'ssur.cc', 'st.news', 'st8.fm', 'stan.md', 'stanford.io', 'starz.tv', 'stmodel.com', 'storycor.ps', 'stspg.io', 'stts.in', 'stuf.in', 'sumal.ly', 'suo.fyi', 'suo.im', 'supr.cl', 'supr.link', 'surl.li', 'svy.mk', 'swa.is', 'swag.run', 'swiy.co', 'swoo.sh', 'swtt.cc', 'sy.to', 'syb.la', 'synd.co', 'syw.co', 't-bi.link', 't-mo.co', 't.cn', 't.co', 't.iotex.me', 't.libren.ms', 't.ly', 't.me', 't.tl', 't1p.de', 't2m.io', 'ta.co', 'tabsoft.co', 'taiwangov.com', 'tanks.ly', 'tbb.tw', 'tbrd.co', 'tcat.tc', 'tcrn.ch', 'tdrive.li', 'tdy.sg', 'tek.io', 'temu.to', 'ter.li', 'tg.pe', 'tgam.ca', 'tgr.ph', 'thatis.me', 'thd.co', 'thedo.do', 'thefp.pub', 'thein.fo', 'thesne.ws', 'thetim.es', 'thght.works', 'thinfi.com', 'thls.co', 'thn.news', 'thr.cm', 'thrill.to', 'ti.me', 'tibco.cm', 'tibco.co', 'tidd.ly', 'tim.com.vc', 'tinu.be', 'tiny.cc', 'tiny.ee', 'tiny.one', 'tiny.pl', 'tinyarro.ws', 'tinylink.net', 'tinyurl.com', 'tinyurl.hu', 'tinyurl.mobi', 'tktwb.tw', 'tl.gd', 'tlil.nl', 'tlrk.it', 'tmblr.co', 'tmsnrt.rs', 'tmz.me', 'tnne.ws', 'tnsne.ws', 'tnvge.co', 'tnw.to', 'tny.cz', 'tny.im', 'tny.so', 'to.ly', 'to.pbs.org', 'toi.in', 'tokopedia.link', 'tonyr.co', 'topt.al', 'toyota.us', 'tpc.io', 'tpmr.com', 'tprk.us', 'tr.ee', 'trackurl.link', 'trade.re', 'travl.rs', 'trib.al', 'trib.in', 'troy.hn', 'trt.sh', 'trymongodb.com', 'tsbk.tw', 'tsta.rs', 'tt.vg', 'tvote.org', 'tw.rog.gg', 'tw.sv', 'twb.nz', 'twm5g.co', 'twou.co', 'twtr.to', 'txdl.top', 'txul.cn', 'u.nu', 'u.shxj.pw', 'u.to', 'u1.mnge.co', 'ua.rog.gg', 'uafly.co', 'ubm.io', 'ubnt.link', 'ubr.to', 'ucbexed.org', 'ucla.in', 'ufcqc.link', 'ugp.io', 'ui8.ru', 'uk.rog.gg', 'ukf.me', 'ukoeln.de', 'ul.rs', 'ul.to', 'ul3.ir', 'ulvis.net', 'ume.la', 'umlib.us', 'unc.live', 'undrarmr.co', 'uni.cf', 'unipapa.co', 'uofr.us', 'uoft.me', 'up.to', 'upmchp.us', 'ur3.us', 'urb.tf', 'urbn.is', 'url.cn', 'url.cy', 'url.ie', 'url2.fr', 'urla.ru', 'urlgeni.us', 'urli.ai', 'urlify.cn', 'urlr.me', 'urls.fr', 'urls.kr', 'urluno.com', 'urly.co', 'urly.fi', 'urlz.fr', 'urlzs.com', 'urt.io', 'us.rog.gg', 'usanet.tv', 'usat.ly', 'usm.ag', 'utm.to', 'utn.pl', 'utraker.com', 'v.gd', 'v.redd.it', 'vai.la', 'vbly.us', 'vd55.com', 'vercel.link', 'vi.sa', 'vi.tc', 'viaalto.me', 'viaja.am', 'vineland.dj', 'viraln.co', 'vivo.tl', 'vk.cc', 'vk.sv', 'vn.rog.gg', 'vntyfr.com', 'vo.la', 'vodafone.uk', 'vogue.cm', 'voicetu.be', 'volvocars.us', 'vonq.io', 'vrnda.us', 'vtns.io', 'vur.me', 'vurl.com', 'vvnt.co', 'vxn.link', 'vypij.bar', 'vz.to', 'vzturl.com', 'w.idg.de', 'w.wiki', 'w5n.co', 'wa.link', 'wa.me', 'wa.sv', 'waa.ai', 'waad.co', 'wahoowa.net', 'walk.sc', 'walkjc.org', 'wapo.st', 'warby.me', 'warp.plus', 'wartsi.ly', 'way.to', 'wb.md', 'wbby.co', 'wbur.fm', 'wbze.de', 'wcha.it', 'we.co', 'weall.vote', 'weare.rs', 'wee.so', 'wef.ch', 'wellc.me', 'wenk.io', 'wf0.xin', 'whatel.se', 'whcs.law', 'whi.ch', 'whoel.se', 'whr.tn', 'wi.se', 'win.gs', 'wit.to', 'wjcf.co', 'wkf.ms', 'wmojo.com', 'wn.nr', 'wndrfl.co', 'wo.ws', 'wooo.tw', 'wp.me', 'wpbeg.in', 'wrctr.co', 'wrd.cm', 'wrem.it', 'wun.io', 'ww7.fr', 'wwf.to', 'wwp.news', 'www.shrunken.com', 'x.gd', 'xbx.lv', 'xerox.bz', 'xfin.tv', 'xfl.ag', 'xfru.it', 'xgam.es', 'xor.tw', 'xpr.li', 'xprt.re', 'xqss.org', 'xrds.ca', 'xrl.us', 'xurl.es', 'xvirt.it', 'xyvid.tv', 'y.ahoo.it', 'y2u.be', 'yadi.sk', 'yal.su', 'yelp.to', 'yex.tt', 'yhoo.it', 'yip.su', 'yji.tw', 'ynews.page.link', 'yoox.ly', 'your.ls', 'yourls.org', 'yourwish.es', 'youtu.be', 'yubi.co', 'yun.ir', 'z23.ru', 'zat.ink', 'zaya.io', 'zc.vg', 'zcu.io', 'zd.net', 'zdrive.li', 'zdsk.co', 'zecz.ec', 'zeep.ly', 'zez.kr', 'zi.ma', 'ziadi.co', 'zipurl.fr', 'zln.do', 'zlr.my', 'zlra.co', 'zlw.re', 'zoho.to', 'zopen.to', 'zovpart.com', 'zpr.io', 'zuki.ie', 'zuplo.link', 'zurb.us', 'zurins.uk', 'zurl.co', 'zurl.ir', 'zurl.ws', 'zws.im', 'zxc.li', 'zynga.my', 'zywv.us', 'zzb.bz', 'zzu.info'
}
tld_extract = tldextract.TLDExtract(cache_dir='.tldextract_cache')

# All expected feature keys (from classifier)
EXPECTED_FEATURES = {
    "dns_a_presence", "dns_a_count",
    "dns_mx_presence", "dns_mx_count",
    "dns_txt_presence", "dns_txt_count",
    "dns_ns_presence", "dns_ns_count",
    "dns_spf_presence", "dns_spf_count",
    "dns_dkim_presence", "dns_dkim_count",
    "dns_dmarc_presence", "dns_dmarc_count",
    "has_ssl_certificate", "ssl_certificate_valid", "ssl_days_to_expiry",
    "ssl_is_expired", "ssl_is_self_signed", "ssl_has_chain_issues",
    "ssl_hostname_mismatch", "ssl_connection_error",
    "domain_age_days", "time_to_expiration",
    "redirect_count", "final_url_diff", "response_time", "content_length",
    "has_title", "title_length", "has_iframe", "num_iframes",
    "has_text_input", "has_password_input", "has_button", "has_image",
    "has_submit", "has_link", "num_links", "num_images", "num_scripts",
    "has_javascript", "has_favicon", "num_a_tags",
    "has_xss_protection", "has_csp", "has_hsts", "has_x_frame_options",
    "has_x_content_type_options", "has_referrer_policy", "has_feature_policy",
    "has_cookie", "has_http_only_cookie", "has_secure_cookie",
}

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def test_https_support(hostname: str) -> bool:
    if not hostname or not is_valid_domain(hostname):
        return False
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # Skip hostname verification (we just want connection)
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception as e:
        logger.debug(f"HTTPS test failed for {hostname}: {e}")
        return False

def ensure_scheme(url: str) -> str:
    url = url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = f"http://{url}"
    return url

def entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def get_registered_domain(hostname: str) -> str:
    if not hostname:
        return ""
    extracted = tld_extract(hostname)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return hostname

def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
        return False
    if domain.lower() in ["localhost", "127.0.0.1"]:
        return False
    return True

# ------------------------------------------------------------------
# Lexical Features
# ------------------------------------------------------------------
def lexical(url: str) -> dict:
    comp = get_url_components(url)
    u, h, d, s, p, q = (
        comp["url"],
        comp["hostname"] or "",
        comp["domain"] or "",
        comp["suffix"] or "",
        comp["path"] or "",
        comp["query"] or "",
    )
    feats = dict(
        url_length=len(u),
        hostname_length=len(h),
        path_length=len(p),
        query_length=len(q),
        domain_length=len(d),
        subdomain_length=len(comp["subdomain"] or ""),
        tld_length=len(s),
        count_dot=u.count("."),
        count_hyphen=u.count("-"),
        count_underline=u.count("_"),
        count_slash=u.count("/"),
        count_question=u.count("?"),
        count_equal=u.count("="),
        count_at=u.count("@"),
        count_and=u.count("&"),
        count_exclamation=u.count("!"),
        count_space=u.count(" "),
        count_tilde=u.count("~"),
        count_comma=u.count(","),
        count_plus=u.count("+"),
        count_asterisk=u.count("*"),
        count_hashtag=u.count("#"),
        count_dollar=u.count("$"),
        count_percent=u.count("%"),
        count_digits=sum(c.isdigit() for c in u),
        count_letters=sum(c.isalpha() for c in u),
        count_special_chars=len(u) - sum(c.isdigit() for c in u) - sum(c.isalpha() for c in u),
        count_encoded_chars=len(re.findall(r"%[0-9a-fA-F]{2}", u)),
        count_subdomains=(comp["subdomain"] or "").count(".") + 1 if comp["subdomain"] else 0,
        count_path_levels=max(0, p.count("/") - 1) if p.startswith("/") else p.count("/"),
        count_query_params=len(q.split("&")) if q else 0,
        has_ip_address=1 if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", h) else 0,
        has_https=1 if test_https_support(h) else 0,
        has_suspicious_tld=1 if s in SUSPICIOUS_TLDS else 0,
        is_shortened=1 if comp["registered_domain"] in SHORTENING_SERVICES else 0,
        has_at_symbol=1 if "@" in u else 0,
        has_double_slash_in_path=1 if "//" in p[1:] else 0,
        has_sensitive_words=1 if re.search(
            r"login|signin|password|account|update|secure|verify|banking|ebay|paypal|admin|cmd|shell|script",
            u, re.I) else 0,
        has_hex_encoding=1 if re.search(r"%[0-9a-fA-F]{2}", u) else 0,
        has_port_in_url=1 if comp["netloc"] and ":" in comp["netloc"] and not comp["netloc"].endswith((":80", ":443")) else 0,
        has_query=1 if q else 0,
        has_fragment=1 if comp["fragment"] else 0,
    )

    for label, tokens in (
        ("path", re.split(r"[/\-_.]", p)),
        ("domain", re.split(r"[\-_.]", d)),
        ("hostname", re.split(r"[\-_.]", h)),
    ):
        tokens = [t for t in tokens if t]
        feats[f"num_{label}_tokens"] = len(tokens)
        feats[f"avg_{label}_token_length"] = sum(len(t) for t in tokens) / len(tokens) if tokens else 0
        feats[f"max_{label}_token_length"] = max((len(t) for t in tokens), default=0)

    for name, text in (("url", u), ("hostname", h), ("path", p), ("query", q), ("domain", d)):
        feats[f"entropy_{name}"] = entropy(text)

    feats["ratio_digits_url"] = feats["count_digits"] / max(feats["url_length"], 1)
    feats["ratio_letters_url"] = feats["count_letters"] / max(feats["url_length"], 1)
    feats["ratio_special_chars_url"] = feats["count_special_chars"] / max(feats["url_length"], 1)
    feats["ratio_digits_hostname"] = sum(c.isdigit() for c in h) / max(len(h), 1)
    feats["ratio_digits_path"] = sum(c.isdigit() for c in p) / max(len(p), 1)
    feats["ratio_digits_query"] = sum(c.isdigit() for c in q) / max(len(q), 1)

    feats.update(
        first_digit_index=next((i for i, c in enumerate(u) if c.isdigit()), -1),
        first_letter_index=next((i for i, c in enumerate(u) if c.isalpha()), -1),
        first_slash_index=u.find("/"),
        last_slash_index=u.rfind("/"),
        first_dot_index=u.find("."),
        last_dot_index=u.rfind("."),
    )
    return feats

def get_url_components(url: str) -> dict:
    url = ensure_scheme(url)
    parsed = urlparse(url)
    ext = tld_extract(parsed.netloc.split(':')[0])
    return dict(
        url=url,
        scheme=parsed.scheme,
        netloc=parsed.netloc,
        hostname=parsed.hostname,
        domain=ext.domain,
        subdomain=ext.subdomain,
        suffix=ext.suffix,
        registered_domain=get_registered_domain(parsed.hostname),
        path=parsed.path,
        query=parsed.query,
        fragment=parsed.fragment,
    )

# ------------------------------------------------------------------
# DNS Features
# ------------------------------------------------------------------
def dns_features(domain: str) -> dict:
    defaults = {
        "dns_a_presence": None, "dns_a_count": None,
        "dns_mx_presence": None, "dns_mx_count": None,
        "dns_txt_presence": None, "dns_txt_count": None,
        "dns_ns_presence": None, "dns_ns_count": None,
        "dns_spf_presence": None, "dns_spf_count": None,
        "dns_dkim_presence": None, "dns_dkim_count": None,
        "dns_dmarc_presence": None, "dns_dmarc_count": None,
    }
    if not is_valid_domain(domain):
        return defaults

    try:
        # A Record
        try:
            ans = dns.resolver.resolve(domain, 'A')
            defaults.update(dns_a_presence=1, dns_a_count=len(ans))
        except Exception:
            defaults.update(dns_a_presence=0, dns_a_count=0)

        # MX Record
        try:
            ans = dns.resolver.resolve(domain, 'MX')
            defaults.update(dns_mx_presence=1, dns_mx_count=len(ans))
        except Exception:
            defaults.update(dns_mx_presence=0, dns_mx_count=0)

        # TXT + SPF
        try:
            ans = dns.resolver.resolve(domain, 'TXT')
            defaults.update(dns_txt_presence=1, dns_txt_count=len(ans))
            spf_count = sum(1 for r in ans if b"v=spf1" in r.to_text().encode())
            defaults.update(dns_spf_presence=1 if spf_count > 0 else 0, dns_spf_count=spf_count)
        except Exception:
            defaults.update(dns_txt_presence=0, dns_txt_count=0, dns_spf_presence=0, dns_spf_count=0)

        # NS Record
        try:
            ans = dns.resolver.resolve(domain, 'NS')
            defaults.update(dns_ns_presence=1, dns_ns_count=len(ans))
        except Exception:
            defaults.update(dns_ns_presence=0, dns_ns_count=0)

        # DKIM
        try:
            dkim_domain = f"default._domainkey.{domain}"
            ans = dns.resolver.resolve(dkim_domain, 'TXT')
            defaults.update(dns_dkim_presence=1, dns_dkim_count=len(ans))
        except Exception:
            defaults.update(dns_dkim_presence=0, dns_dkim_count=0)

        # DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            ans = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_count = sum(1 for r in ans if b"v=dmarc1" in r.to_text().encode())
            defaults.update(dns_dmarc_presence=1 if dmarc_count > 0 else 0, dns_dmarc_count=dmarc_count)
        except Exception:
            defaults.update(dns_dmarc_presence=0, dns_dmarc_count=0)

    except Exception as e:
        logger.error(f"DNS error for {domain}: {e}")
    return defaults

# ------------------------------------------------------------------
# HTTP & HTML Features (with Cloudscraper)
# ------------------------------------------------------------------
def http_and_html(url: str) -> tuple:
    url = ensure_scheme(url)
    scraper = cloudscraper.create_scraper(
        browser={'browser': 'firefox', 'platform': 'windows', 'mobile': False},
        delay=10
    )
    
    # Try both HTTP and HTTPS if the original scheme fails
    original_scheme = urlparse(url).scheme
    schemes_to_try = [original_scheme]
    
    # If original is HTTPS, also try HTTP as fallback
    if original_scheme == 'https':
        schemes_to_try.append('http')
    # If original is HTTP, also try HTTPS as fallback
    elif original_scheme == 'http':
        schemes_to_try.append('https')
    
    for scheme in schemes_to_try:
        try:
            # Replace scheme
            parsed_url = urlparse(url)
            test_url = f"{scheme}://{parsed_url.netloc}{parsed_url.path}"
            if parsed_url.query:
                test_url += f"?{parsed_url.query}"
            if parsed_url.fragment:
                test_url += f"#{parsed_url.fragment}"
            
            logger.info(f"Trying {test_url}")
            
            resp = scraper.get(test_url, timeout=55, allow_redirects=True)
            status = resp.status_code
            headers = {k.lower(): v for k, v in resp.headers.items()}
            html = resp.text
            logger.info(f"Successfully fetched {test_url} | Status: {status} | Redirects: {len(resp.history)}")
            
            # If successful, break out of the loop
            break
            
        except Exception as e:
            logger.warning(f"HTTP error for {test_url}: {e}")
            # If this was the last scheme to try, return failure
            if scheme == schemes_to_try[-1]:
                return 0, {}
            continue
    
    feats = {
        "redirect_count": len(resp.history),
        "final_url_diff": int(str(resp.url).lower() != url.lower()),
        "response_time": resp.elapsed.total_seconds(),
        "content_length": len(resp.content),
        "has_title": 0, "title_length": 0,
        "has_iframe": 0, "num_iframes": 0,
        "has_text_input": 0, "has_password_input": 0,
        "has_button": 0, "has_image": 0,
        "has_submit": 0, "has_link": 0,
        "num_links": 0, "num_images": 0, "num_scripts": 0,
        "has_javascript": 0, "has_favicon": 0, "num_a_tags": 0,
        "has_xss_protection": 0, "has_csp": 0, "has_hsts": 0,
        "has_x_frame_options": 0, "has_x_content_type_options": 0,
        "has_referrer_policy": 0, "has_feature_policy": 0,
        "has_cookie": 0, "has_http_only_cookie": 0, "has_secure_cookie": 0,
    }

    if status == 200 and html:
        soup = BeautifulSoup(html, "lxml")
        title = soup.find("title")
        if title and title.get_text(strip=True):
            feats.update(has_title=1, title_length=len(title.get_text(strip=True)))

        feats.update(
            num_iframes=len(soup.find_all("iframe")),
            has_iframe=int(len(soup.find_all("iframe")) > 0),
            num_scripts=len(soup.find_all("script")),
            has_javascript=int(len(soup.find_all("script")) > 0),
            num_links=len(soup.find_all("a", href=True)),
            has_link=int(len(soup.find_all("a", href=True)) > 0),
            num_images=len(soup.find_all("img")),
            has_image=int(len(soup.find_all("img")) > 0),
            num_a_tags=len(soup.find_all("a")),
            has_text_input=int(soup.find("input", type=lambda t: t in {"text", "email", "search"}) is not None),
            has_password_input=int(soup.find("input", type="password") is not None),
            has_button=int(soup.find("button") is not None),
            has_submit=int(soup.find("input", type="submit") is not None or soup.find("button", type="submit") is not None),
            has_favicon=int(soup.find("link", rel=lambda r: r and "icon" in r.lower()) is not None),
        )

        sec_headers = {
            "x-xss-protection": "has_xss_protection",
            "content-security-policy": "has_csp",
            "strict-transport-security": "has_hsts",
            "x-frame-options": "has_x_frame_options",
            "x-content-type-options": "has_x_content_type_options",
            "referrer-policy": "has_referrer_policy",
            "feature-policy": "has_feature_policy"
        }
        for hdr, feat in sec_headers.items():
            if hdr in headers:
                feats[feat] = 1

        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            feats["has_cookie"] = 1
            sc = set_cookie.lower()
            feats["has_http_only_cookie"] = int("httponly" in sc)
            feats["has_secure_cookie"] = int("secure" in sc)

    return status, feats

# ------------------------------------------------------------------
# SSL Certificate Features
# ------------------------------------------------------------------
def ssl_features(hostname: str) -> dict:
    feats = {
        "has_ssl_certificate": None,
        "ssl_certificate_valid": None,
        "ssl_days_to_expiry": None,
        "ssl_is_expired": None,
        "ssl_is_self_signed": None,
        "ssl_has_chain_issues": None,
        "ssl_hostname_mismatch": None,
        "ssl_connection_error": None,
    }
    if not hostname or not is_valid_domain(hostname):
        feats["ssl_connection_error"] = 1
        return feats

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
        feats.update(has_ssl_certificate=1, ssl_certificate_valid=1)

        expiry = cert.get("notAfter")
        if expiry:
            exp_date = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp_date - datetime.now(timezone.utc)).days
            feats.update(
                ssl_days_to_expiry=days,
                ssl_is_expired=int(days < 0),
                ssl_is_self_signed=0,
                ssl_has_chain_issues=0,
                ssl_hostname_mismatch=0,
                ssl_connection_error=0
            )
        else:
            feats.update(ssl_days_to_expiry=-1, ssl_is_expired=0)
    except ssl.CertificateError as e:
        feats.update(ssl_certificate_valid=0, ssl_connection_error=0)
        if "hostname" in str(e).lower():
            feats["ssl_hostname_mismatch"] = 1
        if "expired" in str(e).lower():
            feats["ssl_is_expired"] = 1
    except ssl.SSLError:
        feats.update(ssl_certificate_valid=0, ssl_has_chain_issues=1, ssl_connection_error=1)
    except (ConnectionRefusedError, OSError):
        feats["ssl_connection_error"] = 1
    except Exception as e:
        logger.warning(f"SSL error for {hostname}: {e}")
        feats["ssl_connection_error"] = 1

    for k in ["has_ssl_certificate", "ssl_certificate_valid", "ssl_days_to_expiry",
              "ssl_is_expired", "ssl_is_self_signed", "ssl_has_chain_issues",
              "ssl_hostname_mismatch", "ssl_connection_error"]:
        if feats[k] is None:
            feats[k] = 0 if k != "ssl_days_to_expiry" else -1
    return feats

# ------------------------------------------------------------------
# WHOIS Features
# ------------------------------------------------------------------
def whois_features(domain: str) -> dict:
    if not is_valid_domain(domain):
        return {"domain_age_days": None, "time_to_expiration": None}
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        ed = w.expiration_date

        if isinstance(cd, list): cd = cd[0]
        if isinstance(ed, list): ed = ed[0]

        age = (datetime.now(timezone.utc) - cd).days if cd else None
        expiry = (ed - datetime.now(timezone.utc)).days if ed else None

        return {"domain_age_days": age, "time_to_expiration": expiry}
    except Exception as e:
        logger.warning(f"WHOIS failed for {domain}: {e}")
        return {"domain_age_days": None, "time_to_expiration": None}

# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------
def extract_all(url: str) -> dict:
    url = ensure_scheme(url)
    comp = get_url_components(url)
    hostname = comp["hostname"]
    domain = comp["registered_domain"] or ""

    feats = {}
    feats.update(lexical(url))

    status, html_feats = http_and_html(url)
    feats.update(html_feats)

    feats.update(ssl_features(hostname))
    feats.update(whois_features(domain))
    feats.update(dns_features(domain))

    for key in EXPECTED_FEATURES:
        if key not in feats:
            feats[key] = 0 if "presence" in key or "count" in key else None

    feats.update(
        is_active=int(200 <= status <= 299),
        has_redirect=int(feats.get("redirect_count", 0) > 0),
        http_status=status
    )
    
    # Debug: Print number of features and any extras
    print(f"Total features extracted: {len(feats)}")
    if len(feats) != len(EXPECTED_FEATURES):
        extra_features = set(feats.keys()) - EXPECTED_FEATURES
        missing_features = EXPECTED_FEATURES - set(feats.keys())
        print(f"Extra features: {extra_features}")
        print(f"Missing features: {missing_features}")
    
    return feats
def extract_allOld(url: str) -> dict:
    url = ensure_scheme(url)
    comp = get_url_components(url)
    hostname = comp["hostname"]
    domain = comp["registered_domain"] or ""

    feats = {}
    feats.update(lexical(url))

    status, html_feats = http_and_html(url)
    feats.update(html_feats)

    feats.update(ssl_features(hostname))
    feats.update(whois_features(domain))
    feats.update(dns_features(domain))

    for key in EXPECTED_FEATURES:
        if key not in feats:
            feats[key] = 0 if "presence" in key or "count" in key else None

    feats.update(
        is_active=int(200 <= status <= 299),
        has_redirect=int(feats.get("redirect_count", 0) > 0),
        http_status=status
    )

    return feats