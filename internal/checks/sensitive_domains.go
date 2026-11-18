package checks

// sensitiveDomains are sites whose sign-in a hosts-file redirect would phish:
// sign-in pages and mail, crypto exchanges and wallets, payment services, and
// the main banks and wallets of the countries people here work with. A name
// matches when it is one of these or under one ("online.vietcombank.com.vn").
var sensitiveDomains = []string{
	// Sign-in, mail, cloud and code.
	"google.com", "gmail.com", "googleapis.com", "microsoftonline.com", "live.com", "outlook.com", "office.com",
	"microsoft.com", "apple.com", "icloud.com", "facebook.com", "instagram.com", "github.com", "gitlab.com",
	"cloudflare.com", "amazon.com", "aws.amazon.com", "zalo.me",

	// Crypto exchanges and wallets.
	"binance.com", "coinbase.com", "okx.com", "bybit.com", "kraken.com", "metamask.io", "crypto.com", "kucoin.com",
	"bitget.com", "gate.io", "htx.com", "mexc.com", "bitfinex.com", "gemini.com", "bitstamp.net", "upbit.com",
	"trustwallet.com", "phantom.app", "exodus.com", "ledger.com", "trezor.io", "blockchain.com", "myetherwallet.com",
	"rabby.io", "rainbow.me", "keplr.app", "solflare.com", "tonkeeper.com", "uniswap.org", "opensea.io",

	// Payments, wallets and money transfer, worldwide and for online sellers.
	"paypal.com", "stripe.com", "shopify.com", "wise.com", "revolut.com", "payoneer.com", "pingpongx.com",
	"airwallex.com", "worldfirst.com", "lianlianglobal.com", "skrill.com", "neteller.com", "venmo.com", "cash.app",
	"zellepay.com", "alipay.com", "pay.weixin.qq.com", "paytm.com", "gcash.com", "grab.com", "klarna.com",
	"adyen.com", "squareup.com", "wealthsimple.com",

	// Vietnam.
	"vietcombank.com.vn", "techcombank.com", "techcombank.com.vn", "vpbank.com.vn", "mbbank.com.vn", "bidv.com.vn",
	"vietinbank.vn", "acb.com.vn", "tpb.vn", "sacombank.com", "sacombank.com.vn", "agribank.com.vn", "vib.com.vn",
	"shb.com.vn", "hdbank.com.vn", "ocb.com.vn", "msb.com.vn", "momo.vn", "zalopay.vn", "vnpay.vn",

	// United States.
	"chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com", "capitalone.com", "usbank.com",
	"pnc.com", "truist.com", "ally.com", "schwab.com", "fidelity.com", "americanexpress.com", "discover.com",
	"robinhood.com", "mercury.com", "brex.com",

	// Singapore.
	"dbs.com", "dbs.com.sg", "ocbc.com", "uob.com.sg",

	// United Kingdom.
	"barclays.co.uk", "hsbc.co.uk", "hsbc.com", "lloydsbank.com", "natwest.com", "rbs.co.uk", "santander.co.uk",
	"nationwide.co.uk", "halifax.co.uk", "monzo.com", "starlingbank.com",

	// Australia.
	"commbank.com.au", "westpac.com.au", "anz.com", "anz.com.au", "nab.com.au", "macquarie.com.au",

	// United Arab Emirates.
	"emiratesnbd.com", "bankfab.com", "adcb.com", "mashreq.com", "dib.ae", "adib.ae",

	// France.
	"credit-agricole.fr", "bnpparibas.net", "mabanque.bnpparibas", "societegenerale.fr", "labanquepostale.fr",
	"lcl.fr", "boursorama.com", "caisse-epargne.fr", "banquepopulaire.fr", "creditmutuel.fr", "lydia-app.com",

	// Germany.
	"deutsche-bank.de", "commerzbank.de", "sparkasse.de", "dkb.de", "ing.de", "n26.com", "comdirect.de",
	"postbank.de",

	// Italy.
	"intesasanpaolo.com", "unicredit.it", "poste.it", "bancobpm.it", "finecobank.com", "satispay.com",

	// Switzerland.
	"ubs.com", "credit-suisse.com", "postfinance.ch", "raiffeisen.ch", "zkb.ch", "twint.ch",

	// Canada.
	"rbc.com", "rbcroyalbank.com", "td.com", "scotiabank.com", "bmo.com", "cibc.com", "desjardins.com", "interac.ca",

	// Elsewhere in Europe.
	"ing.nl", "rabobank.nl", "abnamro.nl", "santander.com", "bbva.com", "caixabank.es",

	// Elsewhere in Asia.
	"mufg.jp", "smbc.co.jp", "mizuhobank.co.jp", "rakuten-bank.co.jp", "paypay.ne.jp", "kbstar.com", "shinhan.com",
	"kakaobank.com", "toss.im", "hsbc.com.hk", "bochk.com", "icbc.com.cn", "ccb.com", "boc.cn", "cmbchina.com",
	"sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "kasikornbank.com", "scb.co.th", "bca.co.id",
	"maybank2u.com.my", "cimb.com", "bdo.com.ph", "bpi.com.ph",
}
