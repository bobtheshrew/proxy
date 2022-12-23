function FindProxyForURL(url, host)
{
 
 /* Normalize the URL for pattern matching */
 url = url.toLowerCase();
 host = host.toLowerCase();
 
 const whitelist = ["abc.com",
"abebooks.com",
"affordabletours.com",
"albany.edu",
"albanyny.org",
"amazon.com",
"ancestry",
"answers.com",
"aol.com",
"apfco.com",
"apple.com",
"archinform.net",
"archive.org",
"ask.com",
"bankoncit.com",
"barnesandnoble.com",
"bavarianmanor.com",
"bleepingcomputer.com",
"blogspot.com",
"boardgamegeek.com",
"btol.com",
"c.comenity.net",
"capitalone.com",
"caremark.com",
"ccsna.org",
"chase.com",
"christianfilmdatabase.com",
"chuckthewriter.com",
"citi.com",
"citizensbankonline.com",
"coats-of-arms.com",
"colonielibrary.org",
"crossroadsinitiative.com",
"csealocal1000.org",
"davidrumsey.com",
"delange.org",
"deptorg.knox.edu",
"doanestuart.org",
"dowd.org.uk",
"dynamiccatholic.com",
"ebay.com",
"ebooksread.com",
"eclinicalweb.com",
"ecrater.com",
"edwardjones.com",
"edwardjones.com",
"enotes.com",
"espn.com",
"etapestry.com",
"etsy.com",
"ewtn.com",
"facebook.com",
"familysearch.org",
"fbcdn.net",
"flaglercounty.org",
"followmyhealth.com",
"fultonhistory.com",
"geico.com",
"genealogy.com",
"ggpht.com",
"github.com",
"githubassets.com",
"githubusercontent.com",
"go.com",
"google.com",
"googlegroups.com",
"gvt1.com",
"googleusercontent.com",
"googleapis.com",
"googledrive.com",
"gstatic.com",
"gutenberg.org",
"hist-stmarys.org",
"historic-albany.org",
"historicipswich.org",
"hylbom.com",
"ikea.com",
"irish-genealogy-toolkit.com",
"irishgenealogy.ie",
"irs.gov",
"isbndb.com",
"jhfunds.com",
"kiplinger.com",
"legacy.com",
"lhblogs.com",
"livingplaces.com",
"loreley-info.com",
"macys.com",
"marriott.com",
"microsoft.com",
"mlb.com",
"mozilla.com",
"murderbygaslight.com",
"musiciansofmaalwyck.org",
"myfranciscan.org",
"myhealthrecord.com",
"neurologicalassociatesofalbany.com",
"newyorkstatesearch.com",
"newrelic.com",
"nlsbard.loc.gov",
"nrsservicecenter.com",
"nyfalls.com",
"nypost.com",
"nysed.gov",
"nytimes.com",
"odubhda-odowdclan.com",
"odubhdaclan.com",
"oldmaid.blog.co.uk",
"papalaudience.org",
"photobucket.com",
"proboards.com",
"propfaith.net",
"rebelpuritan.com",
"resources.hewitt.com",
"router.asus.com",
"rs6.net",
"scribd.com",
"sefcu.com",
"serverfault.com",
"shannonskinner.com",
"shoprite.com",
"siena.edu",
"sjsachurch.org",
"stackoverflow.com",
"swimmingholes.org",
"t-mobile.com",
"target.com",
"tax.ny.gov",
"tdcardservices.com",
"timeanddate.com",
"timesunion.com",
"timesunion.com",
"trinity-health.com",
"tripadvisor.com",
"tacdn.com",
"uhls.org",
"usatoday.com",
"usatoday.idmanagedsolutions.com",
"usgwarchives.org",
"verizon.com",
"verizonfoundation.org",
"villageofmenands.com",
"wamc.org",
"wamhomecenter.com",
"wellsfargo.com",
"wikimedia.org",
"wikipedia.org",
"wikitravel.org",
"wsj.com",
"yahoo.com",
"youtube.com",
"ytimg.com"
 ];
 
 // add predefined functions to pac
// this._sandBox.importFunction(myIpAddress);
// this._sandBox.importFunction(dnsResolve);
 //this._sandBox.importFunction(proxyAlert, "alert");
 
 let whitelist_length = whitelist.length;
 
 for(let i = 0;i<whitelist_length;i++){
  if (host.includes(whitelist[i].toLowerCase())){
    return 'DIRECT';
  }
  //alert(host + "blocked!");
 }
  
 /* Don't proxy local hostnames */
 if (isPlainHostName(host))
 {
  return 'DIRECT';
 }
 
 /* Don't proxy local domains */
 if (dnsDomainIs(host, ".example1.com") ||
 (host == "example1.com") ||
 dnsDomainIs(host, ".example2.com") ||
 (host == "example2.com") ||
 dnsDomainIs(host, ".example3.com") ||
 (host == "example3.com"))
 {
  return 'DIRECT';
 }
 
 /* Don't proxy Windows Update */
 if ((host == "download.microsoft.com") ||
 (host == "ntservicepack.microsoft.com") ||
 (host == "cdm.microsoft.com") ||
 (host == "wustat.windows.com") ||
 (host == "windowsupdate.microsoft.com") ||
 (dnsDomainIs(host, ".windowsupdate.microsoft.com")) ||
 (host == "update.microsoft.com") ||
 (dnsDomainIs(host, ".update.microsoft.com")) ||
 (dnsDomainIs(host, ".windowsupdate.com")))
 {
  return 'DIRECT';
 }
 
 if (isResolvable(host))
 {
  var hostIP = dnsResolve(host);
 
  /* Don't proxy non-routable addresses (RFC 3330) */
  if (isInNet(hostIP, '0.0.0.0', '255.0.0.0') ||
  isInNet(hostIP, '10.0.0.0', '255.0.0.0') ||
  isInNet(hostIP, '127.0.0.0', '255.0.0.0') ||
  isInNet(hostIP, '169.254.0.0', '255.255.0.0') ||
  isInNet(hostIP, '172.16.0.0', '255.240.0.0') ||
  isInNet(hostIP, '192.0.2.0', '255.255.255.0') ||
  isInNet(hostIP, '192.88.99.0', '255.255.255.0') ||
  isInNet(hostIP, '192.168.0.0', '255.255.0.0') ||
  isInNet(hostIP, '198.18.0.0', '255.254.0.0') ||
  isInNet(hostIP, '224.0.0.0', '240.0.0.0') ||
  isInNet(hostIP, '240.0.0.0', '240.0.0.0'))
  {
   return 'DIRECT';
  }
 
  /* Don't proxy local addresses.*/
  if (false)
  {
   return 'DIRECT';
  }
 }
 
 if (url.substring(0, 5) == 'http:' ||
 url.substring(0, 6) == 'https:' ||
 url.substring(0, 4) == 'ftp:')
 {
  return 'PROXY www.google.com:80';
 }
 
 return 'DIRECT';
}
