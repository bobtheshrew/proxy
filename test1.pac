function FindProxyForURL(url, host)
{
 
 /* Normalize the URL for pattern matching */
 url = url.toLowerCase();
 host = host.toLowerCase();
 
 const whitelist = [
  "bleepingcomputer",
  "github",
  "gstatic",
  "youtube",
  "google",
  "mozilla",
  "nytimes",
  "fbcdn.net",
  "serverfault.com",
  "stackoverflow",
  "t-mobile.com",
"edwardjones.com",
"apfco.com",
"etapestry.com",
"timesunion.com",
"boardgamegeek.com",
"google.com",
"c.comenity.net",
"ccsna.org",
"wikimedia.org",
"blogspot.com",
"deptorg.knox.edu",
"dowd.org.uk",
"dynamiccatholic.com",
"wikipedia.org",
"archinform.net",
"nysed.gov",
"familysearch.org",
"usgwarchives.org",
"yahoo.com",
"genealogy.com",
"microsoft.com",
"historicipswich.org",
"hylbom.com",
"isbndb.com",
"usatoday.com",
"eclinicalweb.com",
"myfranciscan.org",
"nlsbard.loc.gov",
"nypost.com",
"odubhdaclan.com",
"oldmaid.blog.co.uk",
"citi.com",
"capitalone.com",
"target.com",
"wellsfargo.com",
"affordabletours.com",
"router.asus.com",
"photobucket.com",
"go.com",
"ancestry.com",
"shannonskinner.com",
"proboards.com",
"aol.com",
"wikitravel.org",
"abc.com",
"abebooks.com",
"albany.edu",
"albanyny.org",
"amazon.com",
"answers.com",
"apple.com",
"archive.org",
"ask.com",
"bankoncit.com",
"barnesandnoble.com",
"bavarianmanor.com",
"caremark.com",
"chase.com",
"christianfilmdatabase.com",
"chuckthewriter.com",
"citizensbankonline.com",
"coats-of-arms.com",
"crossroadsinitiative.com",
"csealocal1000.org",
"davidrumsey.com",
"delange.org",
"doanestuart.org",
"ebay.com",
"ebooksread.com",
"ecrater.com",
"edwardjones.com",
"enotes.com",
"espn.com",
"etsy.com",
"ewtn.com",
"facebook.com",
"flaglercounty.org",
"fultonhistory.com",
"geico.com",
"google.com",
"gutenberg.org",
"historic-albany.org",
"hist-stmarys.org",
"ikea.com",
"irishgenealogy.ie",
"irish-genealogy-toolkit.com",
"irs.gov",
"jhfunds.com",
"kiplinger.com",
"legacy.com",
"livingplaces.com",
"loreley-info.com",
"macys.com",
"marriott.com",
"mlb.com",
"murderbygaslight.com",
"musiciansofmaalwyck.org",
"newyorkstatesearch.com",
"nrsservicecenter.com",
"nyfalls.com",
"odubhda-odowdclan.com",
"papalaudience.org",
"propfaith.net",
"rebelpuritan.com",
"resources.hewitt.com",
"scribd.com",
"sefcu.com",
"shoprite.com",
"siena.edu",
"sjsachurch.org",
"swimmingholes.org",
"tax.ny.gov",
"tdcardservices.com",
"timeanddate.com",
"timesunion.com",
"usatoday.idmanagedsolutions.com",
"verizon.com",
"verizonfoundation.org",
"villageofmenands.com",
"wamc.org",
"wamhomecenter.com",
"wsj.com",
"lhblogs.com"
 ];
 
 // add predefined functions to pac
// this._sandBox.importFunction(myIpAddress);
// this._sandBox.importFunction(dnsResolve);
 //this._sandBox.importFunction(proxyAlert, "alert");
 
 let whitelist_length = whitelist.length;
 
 for(let i = 0;i<whitelist_length;i++){
  if (host.includes(whitelist[i])){
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
