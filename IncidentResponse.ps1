<# 
        Author: Michael Scott
        http://www.rwnin.net
        https://www.github.com/et0x
        scomijo@gmail.com
        et0x@rwnin.net
        @_et0x
#>

# From: http://data.iana.org/TLD/tlds-alpha-by-domain.txt -- 12/2/2015
$global:TLDS = @('AAA','AARP','ABB','ABBOTT','ABOGADO','AC','ACADEMY','ACCENTURE','ACCOUNTANT','ACCOUNTANTS','ACO','ACTIVE','ACTOR','AD','ADS','ADULT','AE','AEG','AERO','AF','AFL','AG','AGENCY','AI','AIG','AIRFORCE','AIRTEL','AL','ALLFINANZ','ALSACE','AM','AMICA','AMSTERDAM','ANDROID','AO','APARTMENTS','APP','APPLE','AQ','AQUARELLE','AR','ARAMCO','ARCHI','ARMY','ARPA','ARTE','AS','ASIA','ASSOCIATES','AT','ATTORNEY','AU','AUCTION','AUDI','AUDIO','AUTO','AUTOS','AW','AX','AXA','AZ','AZURE','BA','BAND','BANK','BAR','BARCELONA','BARCLAYCARD','BARCLAYS','BARGAINS','BAUHAUS','BAYERN','BB','BBC','BBVA','BCN','BD','BE','BEATS','BEER','BENTLEY','BERLIN','BEST','BET','BF','BG','BH','BHARTI','BI','BIBLE','BID','BIKE','BING','BINGO','BIO','BIZ','BJ','BLACK','BLACKFRIDAY','BLOOMBERG','BLUE','BM','BMS','BMW','BN','BNL','BNPPARIBAS','BO','BOATS','BOEHRINGER','BOM','BOND','BOO','BOOTS','BOSTIK','BOUTIQUE','BR','BRADESCO','BRIDGESTONE','BROADWAY','BROKER','BROTHER','BRUSSELS','BS','BT','BUDAPEST','BUGATTI','BUILD','BUILDERS','BUSINESS','BUZZ','BV','BW','BY','BZ','BZH','CA','CAB','CAFE','CAL','CAMERA','CAMP','CANCERRESEARCH','CANON','CAPETOWN','CAPITAL','CAR','CARAVAN','CARDS','CARE','CAREER','CAREERS','CARS','CARTIER','CASA','CASH','CASINO','CAT','CATERING','CBA','CBN','CC','CD','CEB','CENTER','CEO','CERN','CF','CFA','CFD','CG','CH','CHANEL','CHANNEL','CHAT','CHEAP','CHLOE','CHRISTMAS','CHROME','CHURCH','CI','CIPRIANI','CISCO','CITIC','CITY','CITYEATS','CK','CL','CLAIMS','CLEANING','CLICK','CLINIC','CLOTHING','CLOUD','CLUB','CLUBMED','CM','CN','CO','COACH','CODES','COFFEE','COLLEGE','COLOGNE','COM','COMMBANK','COMMUNITY','COMPANY','COMPUTER','COMSEC','CONDOS','CONSTRUCTION','CONSULTING','CONTRACTORS','COOKING','COOL','COOP','CORSICA','COUNTRY','COUPONS','COURSES','CR','CREDIT','CREDITCARD','CREDITUNION','CRICKET','CROWN','CRS','CRUISES','CSC','CU','CUISINELLA','CV','CW','CX','CY','CYMRU','CYOU','CZ','DABUR','DAD','DANCE','DATE','DATING','DATSUN','DAY','DCLK','DE','DEALS','DEGREE','DELIVERY','DELL','DELTA','DEMOCRAT','DENTAL','DENTIST','DESI','DESIGN','DEV','DIAMONDS','DIET','DIGITAL','DIRECT','DIRECTORY','DISCOUNT','DJ','DK','DM','DNP','DO','DOCS','DOG','DOHA','DOMAINS','DOOSAN','DOWNLOAD','DRIVE','DURBAN','DVAG','DZ','EARTH','EAT','EC','EDU','EDUCATION','EE','EG','EMAIL','EMERCK','ENERGY','ENGINEER','ENGINEERING','ENTERPRISES','EPSON','EQUIPMENT','ER','ERNI','ES','ESQ','ESTATE','ET','EU','EUROVISION','EUS','EVENTS','EVERBANK','EXCHANGE','EXPERT','EXPOSED','EXPRESS','FAGE','FAIL','FAIRWINDS','FAITH','FAMILY','FAN','FANS','FARM','FASHION','FEEDBACK','FERRERO','FI','FILM','FINAL','FINANCE','FINANCIAL','FIRMDALE','FISH','FISHING','FIT','FITNESS','FJ','FK','FLIGHTS','FLORIST','FLOWERS','FLSMIDTH','FLY','FM','FO','FOO','FOOTBALL','FOREX','FORSALE','FORUM','FOUNDATION','FR','FRL','FROGANS','FUND','FURNITURE','FUTBOL','FYI','GA','GAL','GALLERY','GAME','GARDEN','GB','GBIZ','GD','GDN','GE','GEA','GENT','GENTING','GF','GG','GGEE','GH','GI','GIFT','GIFTS','GIVES','GIVING','GL','GLASS','GLE','GLOBAL','GLOBO','GM','GMAIL','GMO','GMX','GN','GOLD','GOLDPOINT','GOLF','GOO','GOOG','GOOGLE','GOP','GOV','GP','GQ','GR','GRAINGER','GRAPHICS','GRATIS','GREEN','GRIPE','GROUP','GS','GT','GU','GUCCI','GUGE','GUIDE','GUITARS','GURU','GW','GY','HAMBURG','HANGOUT','HAUS','HEALTHCARE','HELP','HERE','HERMES','HIPHOP','HITACHI','HIV','HK','HM','HN','HOCKEY','HOLDINGS','HOLIDAY','HOMEDEPOT','HOMES','HONDA','HORSE','HOST','HOSTING','HOTELES','HOTMAIL','HOUSE','HOW','HR','HSBC','HT','HU','HYUNDAI','IBM','ICBC','ICE','ICU','ID','IE','IFM','IINET','IL','IM','IMMO','IMMOBILIEN','IN','INDUSTRIES','INFINITI','INFO','ING','INK','INSTITUTE','INSURE','INT','INTERNATIONAL','INVESTMENTS','IO','IPIRANGA','IQ','IR','IRISH','IS','IST','ISTANBUL','IT','ITAU','IWC','JAGUAR','JAVA','JCB','JE','JETZT','JEWELRY','JLC','JLL','JM','JO','JOBS','JOBURG','JP','JPRS','JUEGOS','KAUFEN','KDDI','KE','KG','KH','KI','KIA','KIM','KINDER','KITCHEN','KIWI','KM','KN','KOELN','KOMATSU','KP','KR','KRD','KRED','KW','KY','KYOTO','KZ','LA','LACAIXA','LAMBORGHINI','LANCASTER','LAND','LANDROVER','LASALLE','LAT','LATROBE','LAW','LAWYER','LB','LC','LDS','LEASE','LECLERC','LEGAL','LEXUS','LGBT','LI','LIAISON','LIDL','LIFE','LIFESTYLE','LIGHTING','LIMITED','LIMO','LINDE','LINK','LIVE','LIXIL','LK','LOAN','LOANS','LOL','LONDON','LOTTE','LOTTO','LOVE','LR','LS','LT','LTD','LTDA','LU','LUPIN','LUXE','LUXURY','LV','LY','MA','MADRID','MAIF','MAISON','MAN','MANAGEMENT','MANGO','MARKET','MARKETING','MARKETS','MARRIOTT','MBA','MC','MD','ME','MEDIA','MEET','MELBOURNE','MEME','MEMORIAL','MEN','MENU','MEO','MG','MH','MIAMI','MICROSOFT','MIL','MINI','MK','ML','MM','MMA','MN','MO','MOBI','MODA','MOE','MOI','MOM','MONASH','MONEY','MONTBLANC','MORMON','MORTGAGE','MOSCOW','MOTORCYCLES','MOV','MOVIE','MOVISTAR','MP','MQ','MR','MS','MT','MTN','MTPC','MTR','MU','MUSEUM','MUTUELLE','MV','MW','MX','MY','MZ','NA','NADEX','NAGOYA','NAME','NAVY','NC','NE','NEC','NET','NETBANK','NETWORK','NEUSTAR','NEW','NEWS','NEXUS','NF','NG','NGO','NHK','NI','NICO','NINJA','NISSAN','NL','NO','NOKIA','NP','NR','NRA','NRW','NTT','NU','NYC','NZ','OBI','OFFICE','OKINAWA','OM','OMEGA','ONE','ONG','ONL','ONLINE','OOO','ORACLE','ORANGE','ORG','ORGANIC','OSAKA','OTSUKA','OVH','PA','PAGE','PANERAI','PARIS','PARTNERS','PARTS','PARTY','PE','PET','PF','PG','PH','PHARMACY','PHILIPS','PHOTO','PHOTOGRAPHY','PHOTOS','PHYSIO','PIAGET','PICS','PICTET','PICTURES','PING','PINK','PIZZA','PK','PL','PLACE','PLAY','PLAYSTATION','PLUMBING','PLUS','PM','PN','POHL','POKER','PORN','POST','PR','PRAXI','PRESS','PRO','PROD','PRODUCTIONS','PROF','PROPERTIES','PROPERTY','PROTECTION','PS','PT','PUB','PW','PY','QA','QPON','QUEBEC','RACING','RE','REALTOR','REALTY','RECIPES','RED','REDSTONE','REHAB','REISE','REISEN','REIT','REN','RENT','RENTALS','REPAIR','REPORT','REPUBLICAN','REST','RESTAURANT','REVIEW','REVIEWS','RICH','RICOH','RIO','RIP','RO','ROCHER','ROCKS','RODEO','RS','RSVP','RU','RUHR','RUN','RW','RWE','RYUKYU','SA','SAARLAND','SAKURA','SALE','SAMSUNG','SANDVIK','SANDVIKCOROMANT','SANOFI','SAP','SAPO','SARL','SAXO','SB','SBS','SC','SCA','SCB','SCHMIDT','SCHOLARSHIPS','SCHOOL','SCHULE','SCHWARZ','SCIENCE','SCOR','SCOT','SD','SE','SEAT','SECURITY','SEEK','SENER','SERVICES','SEVEN','SEW','SEX','SEXY','SFR','SG','SH','SHIKSHA','SHOES','SHOW','SHRIRAM','SI','SINGLES','SITE','SJ','SK','SKI','SKY','SKYPE','SL','SM','SN','SNCF','SO','SOCCER','SOCIAL','SOFTWARE','SOHU','SOLAR','SOLUTIONS','SONY','SOY','SPACE','SPIEGEL','SPREADBETTING','SR','SRL','ST','STADA','STARHUB','STATOIL','STC','STCGROUP','STOCKHOLM','STUDIO','STUDY','STYLE','SU','SUCKS','SUPPLIES','SUPPLY','SUPPORT','SURF','SURGERY','SUZUKI','SV','SWATCH','SWISS','SX','SY','SYDNEY','SYSTEMS','SZ','TAB','TAIPEI','TATAMOTORS','TATAR','TATTOO','TAX','TAXI','TC','TD','TEAM','TECH','TECHNOLOGY','TEL','TELEFONICA','TEMASEK','TENNIS','TF','TG','TH','THD','THEATER','THEATRE','TICKETS','TIENDA','TIPS','TIRES','TIROL','TJ','TK','TL','TM','TN','TO','TODAY','TOKYO','TOOLS','TOP','TORAY','TOSHIBA','TOURS','TOWN','TOYOTA','TOYS','TR','TRADE','TRADING','TRAINING','TRAVEL','TRUST','TT','TUI','TV','TW','TZ','UA','UBS','UG','UK','UNIVERSITY','UNO','UOL','US','UY','UZ','VA','VACATIONS','VANA','VC','VE','VEGAS','VENTURES','VERISIGN','VERSICHERUNG','VET','VG','VI','VIAJES','VIDEO','VILLAS','VIN','VIP','VIRGIN','VISION','VISTA','VISTAPRINT','VIVA','VLAANDEREN','VN','VODKA','VOTE','VOTING','VOTO','VOYAGE','VU','WALES','WALTER','WANG','WATCH','WEBCAM','WEBSITE','WED','WEDDING','WEIR','WF','WHOSWHO','WIEN','WIKI','WILLIAMHILL','WIN','WINDOWS','WINE','WME','WORK','WORKS','WORLD','WS','WTC','WTF','XBOX','XEROX','XIN','XN--11B4C3D','XN--1QQW23A','XN--30RR7Y','XN--3BST00M','XN--3DS443G','XN--3E0B707E','XN--3PXU8K','XN--42C2D9A','XN--45BRJ9C','XN--45Q11C','XN--4GBRIM','XN--55QW42G','XN--55QX5D','XN--6FRZ82G','XN--6QQ986B3XL','XN--80ADXHKS','XN--80AO21A','XN--80ASEHDB','XN--80ASWG','XN--90A3AC','XN--90AIS','XN--9DBQ2A','XN--9ET52U','XN--B4W605FERD','XN--C1AVG','XN--C2BR7G','XN--CG4BKI','XN--CLCHC0EA0B2G2A9GCD','XN--CZR694B','XN--CZRS0T','XN--CZRU2D','XN--D1ACJ3B','XN--D1ALF','XN--EFVY88H','XN--ESTV75G','XN--FHBEI','XN--FIQ228C5HS','XN--FIQ64B','XN--FIQS8S','XN--FIQZ9S','XN--FJQ720A','XN--FLW351E','XN--FPCRJ9C3D','XN--FZC2C9E2C','XN--GECRJ9C','XN--H2BRJ9C','XN--HXT814E','XN--I1B6B1A6A2E','XN--IMR513N','XN--IO0A7I','XN--J1AEF','XN--J1AMH','XN--J6W193G','XN--KCRX77D1X4A','XN--KPRW13D','XN--KPRY57D','XN--KPUT3I','XN--L1ACC','XN--LGBBAT1AD8J','XN--MGB9AWBF','XN--MGBA3A3EJT','XN--MGBA3A4F16A','XN--MGBAAM7A8H','XN--MGBAB2BD','XN--MGBAYH7GPA','XN--MGBBH1A71E','XN--MGBC0A9AZCG','XN--MGBERP4A5D4AR','XN--MGBPL2FH','XN--MGBTX2B','XN--MGBX4CD0AB','XN--MK1BU44C','XN--MXTQ1M','XN--NGBC5AZD','XN--NODE','XN--NQV7F','XN--NQV7FS00EMA','XN--NYQY26A','XN--O3CW4H','XN--OGBPF8FL','XN--P1ACF','XN--P1AI','XN--PGBS0DH','XN--PSSY2U','XN--Q9JYB4C','XN--QCKA1PMC','XN--QXAM','XN--RHQV96G','XN--S9BRJ9C','XN--SES554G','XN--T60B56A','XN--TCKWE','XN--UNUP4Y','XN--VERMGENSBERATER-CTB','XN--VERMGENSBERATUNG-PWB','XN--VHQUV','XN--VUQ861B','XN--WGBH1C','XN--WGBL6A','XN--XHQ521B','XN--XKC2AL3HYE2A','XN--XKC2DL3A5EE0H','XN--Y9A3AQ','XN--YFRO4I67O','XN--YGBI2AMMX','XN--ZFR164B','XPERIA','XXX','XYZ','YACHTS','YAMAXUN','YANDEX','YE','YODOBASHI','YOGA','YOKOHAMA','YOUTUBE','YT','ZA','ZARA','ZIP','ZM','ZONE','ZUERICH','ZW')

function Get-AllProcesses
{
    Param(

        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]$Credentials,

        [switch]$Sorted

    )

    Begin
    {

        [System.Collections.ArrayList]$results = @()


    } Process {

        foreach ($computer in $ComputerName) {

            if ($Credentials) {
                
                $processes = Get-WmiObject -ComputerName $computer -Credential $Credentials -Class Win32_Process -Namespace 'root\cimv2' -Impersonation 3

                if (-not $processes)
                {

                    Write-Error "[!] Error: No access to computer '$computer'"

                }

            } else {

                try
                {

                    $processes = Get-WmiObject -ComputerName $computer -Class Win32_Process -Namespace 'root/cimv2'

                } catch {

                    Write-Error "[!] Error: No access to computer '$computer'"

                    return 0

                }

            }

            ForEach ($p in $processes) {

                $results.add($p.ExecutablePath) | Out-Null

            }

        }

    } end {

        if ($Sorted) {

            return ($results | Sort-Object)

        } else {

            return $results

        }

    }

}

function Get-AllServices
{
    Param(

        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]$Credentials,

        [switch]$Sorted

    )

    Begin
    {

        [System.Collections.ArrayList]$results = @()


    } Process {

        foreach ($computer in $ComputerName) {

            if ($Credentials) {

                try
                {

                    $services = Get-WmiObject -ComputerName $computer -Credential $Credentials -Class Win32_Service -Namespace 'root\cimv2' -Impersonation 3

                } catch {

                    return 0

                }

            } else {

                try
                {

                    $services = Get-WmiObject -ComputerName $computer -Class Win32_Service -Namespace 'root/cimv2'

                } catch {

                    Write-Error "[!] Error: No access to computer '$computer'"

                    return 0

                }

            }

            ForEach ($s in $services) {

                $results.add($s.Name) | Out-Null

            }

        }

    } end {

        if ($Sorted) {

            return ($results | Sort-Object)

        } else {

            return $results

        }

    }

}

function Invoke-ProcessHashSweep
{
    Param (

        [string[]]$ComputerNames,

        [switch]$SupplyCreds

    )

    [System.Collections.Hashtable]$results = @{}

    if ($SupplyCreds) {

        $creds = Get-Credential

    }


    foreach ($computer in $ComputerNames)
    {

        if ($SupplyCreds) {

            $p = Get-AllProcesses -ComputerName $Computer -Credentials $creds

        } else {

            $p = Get-AllProcesses -ComputerName $Computer

        }

        if ($p)
        {

            $results[$computer] = Invoke-HashArray -Array $p

        }

    }

    return $results
}

function Invoke-HashArray
{

    Param(

        [System.Collections.ArrayList]$Array

    )

    $text = $Array -join "`r`n"

    $hash = [System.BitConverter]::ToString(

        (New-Object System.Security.Cryptography.MD5CryptoServiceProvider).ComputeHash(

            [system.text.encoding]::UTF8.GetBytes($text)

        )

    )

    return $hash

}

function Invoke-ServiceHashSweep
{
    Param (

        [string[]]$ComputerNames,

        [switch]$SupplyCreds

    )

    [System.Collections.Hashtable]$results = @{}

    if ($SupplyCreds) {

        $creds = Get-Credential

    }


    foreach ($computer in $ComputerNames)
    {

        if ($SupplyCreds) {

            $s = Get-AllServices -ComputerName $Computer -Credentials $creds

        } else {

            $s = Get-AllServices -ComputerName $Computer

        }

        if ($s)
        {
            $results[$computer] = Invoke-HashArray -Array $s
        }

    }

    return $results
}


function Get-Strings
{

    [CmdletBinding()]

        Param(

            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]

            [String]$Data,

            [Int]$Length = 4,

            [Switch]$NetworkItems = $false,

            [Switch]$FileItems = $false,

            [Switch]$RegistryItems = $false,

            [Switch]$EmailItems = $false,

            [Switch]$FunctionItems = $false

        )

    process {

        [string[]]$results = @()

        if ( $NetworkItems )
        {

            $re_domainItems = '(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?'

            $re_ipItems = '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

            $domain_matches = $Data | Select-String -Pattern $re_domainItems -AllMatches

            $ip_matches = $Data | Select-String -Pattern $re_ipItems -AllMatches



            if ($domain_matches.Matches.Count) { 

                $domain_matches.Matches | ForEach-Object { 

                    if ($_.Value.Length -ge $Length)
                    {

                        if (($_.Value.split('.'))[-1].Replace('/','') -in $TLDS )
                        { 

                            $results += $_.Value 

                        }

                    }

                }

            }

            if ($ip_matches.Matches.Count) { 

                $ip_matches.Matches | ForEach-Object { 

                    if ($_.Value.Length -ge $Length)
                    {

                        $results += $_.Value 

                    }

                }

            }

            $results = ( $results | Sort-Object -Unique )

            return $results

        } elseif ( $FileItems ) {
            
            $re_fileItems = '[ -~]+\.[ -~]+'

            $file_matches = $Data | Select-String -Pattern $re_fileItems -AllMatches

            if ($file_matches.Matches.Count) { 

                $file_matches.Matches | ForEach-Object { 

                    if ($_.Value.Length -ge $Length)
                    {

                        $results += $_.Value 

                    }

                }

            }

            $results = ( $results | Sort-Object -Unique )

            return $results

        } elseif ( $RegistryItems ) {
            
            $re_registryItems = '[ -~]*(HKLM|HKCU|HKCR|HKU|HKCC|HKEY|CurrentControlSet)[ -~]*'

            $registry_matches = $Data | Select-String -Pattern $re_registryItems -AllMatches

            if ($registry_matches.Matches.Count) { 

                $registry_matches.Matches | ForEach-Object { 

                    if ($_.Value.Length -ge $Length)
                    {

                        $results += $_.Value 

                    }

                }

            }

            $results = ( $results | Sort-Object -Unique )

            return $results

        } elseif ( $EmailItems ) {
            
            $re_emailItems = "\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*"

            $email_matches = $Data | Select-String -Pattern $re_emailItems -AllMatches

            if ($email_matches.Matches.Count) { 

                $email_matches.Matches | ForEach-Object { 

                    if ($_.Value.Length -ge $Length)
                    {

                        $results += $_.Value 

                    }

                }

            }

            $results = ( $results | Sort-Object -Unique )

            return $results

        } elseif ( $FunctionItems ) {
            
            $re_functionItems = '[A-Z]([A-Z0-9]*[a-z][a-z0-9]*[A-Z]|[a-z0-9]*[A-Z][A-Z0-9]*[a-z])[A-Za-z0-9]*'

            $function_matches = $Data | Select-String -Pattern $re_functionItems -AllMatches -CaseSensitive

            if ($function_matches.Matches.Count) { 

                $function_matches.Matches | ForEach-Object { 

                    if ($_.Value.Length -ge $Length)
                    {

                        $results += $_.Value 

                    }

                }

            }

            $results = ( $results | Sort-Object -Unique )

            return $results

        } else {
            
            $re = "[ -~]{$Length,}"

            $string_matches = $Data | Select-String -Pattern $re -AllMatches

            if ($string_matches.Matches.Count) { 

                $string_matches.Matches | ForEach-Object { 

                    if ($_.Value.Length -ge $Length)
                    {

                        $results += $_.Value 

                    }

                }

            }

        }

        return $results

    } end {

    }

}

function Invoke-HashString
{
    Param(

        [CmdletBinding()]

        [Parameter(Mandatory=$true)]

        [String]$Data

    )

    $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider

    $enc = New-Object -TypeName System.Text.UTF8Encoding

    $hash = [System.BitConverter]::ToString($md5.ComputeHash($enc.GetBytes($Data)))

    return $hash
}


function Get-WMIEventSubscriptions
{

    Param(

        [ValidateSet('All','Filter','Consumer','BindingPath')]

        [String]$Type,

        [Parameter(Mandatory=$true)]

        [String[]]$ComputerNames,

        [Switch]$Credentialed,

        [System.Management.Automation.PSCredential]$ProvideCreds = $null,

        [Switch]$ShowDefinitions = $false

    )

    if ($Credentialed)
    {

        $creds = Get-Credential

    } elseif ($ProvideCreds) {

        $creds = $ProvideCreds
    
    }

    [System.Collections.Hashtable]$results = @{}

    Switch ($Type)
    {
        'All' {

                foreach ($computer in $ComputerNames)
                {

                    if ($Credentialed -or $ProvideCreds)
                    {

                        $Binding = Get-WmiObject -ComputerName $computer -Namespace 'root/subscription' -Class __FilterToConsumerBinding -Credential $creds

                    } else {

                        $Binding = Get-WmiObject -ComputerName $computer -Namespace 'root/subscription' -Class __FilterToConsumerBinding

                    }

                    if ($Binding)
                    {

                        $results[$computer] = @($Binding.__Path, $Binding.Filter, $Binding.Consumer)

                        Remove-Variable Binding -Force

                    }

                }

                return $results

        }

        'BindingPath' {

                foreach ($computer in $ComputerNames)
                {

                    if ($Credentialed -or $ProvideCreds)
                    {

                        $Binding = Get-WmiObject -ComputerName $computer -Namespace 'root/subscription' -Class __FilterToConsumerBinding -Credential $creds

                    } else {

                        $Binding = Get-WmiObject -ComputerName $computer -Namespace 'root/subscription' -Class __FilterToConsumerBinding

                    }

                    if ($Binding)
                    {

                        $results[$computer] = @($Binding.__Path)

                        Remove-Variable Binding -Force

                    }

                }

                return $results

        }

        'Filter' {

            foreach ($computer in $ComputerNames)
            {

                if ($Credentialed -or $ProvideCreds)
                {

                    $Binding = Get-WmiObject -ComputerName $computer -Namespace 'root/subscription' -Class __FilterToConsumerBinding -Credential $creds

                } else {

                    $Binding = Get-WmiObject -ComputerName $computer -Namespace 'root/subscription' -Class __FilterToConsumerBinding

                }

                if ($Binding)
                {

                    $results[$computer] = @($Binding.Filter)

                    Remove-Variable Binding -Force

                }

            }

            return $results
        
        }

        'Consumer' {

            foreach ($computer in $ComputerNames)
            {

                if ($Credentialed -or $ProvideCreds)
                {

                    $Binding = Get-WmiObject -ComputerName $computer -Namespace 'root/subscription' -Class __FilterToConsumerBinding -Credential $creds

                } else {

                    $Binding = Get-WmiObject -ComputerName $computer -Namespace 'root/subscription' -Class __FilterToConsumerBinding

                }

                if ($Binding)
                {

                    $results[$computer] = @($Binding.Consumer)

                    Remove-Variable Binding -Force

                }

            }

            return $results
        
        }

    }

}

function Invoke-ClarifyEventSubscription
{

    Param(

        [CmdletBinding()]

        [Parameter(Mandatory=$true)]

        [String]$ComputerName,

        [Parameter(Mandatory=$true)]

        [String]$BindingPath,

        [Switch]$Credentialed,

        [System.Management.Automation.PSCredential]$ProvideCreds = $null

    )

    $ConsumerProperties = @{

        'CommandLineEventConsumer' = @('Name','CommandLineTemplate','ExecutablePath','WorkingDirectory');

        'NTEventLogEventConsumer'  = @('Name','EventID','EventType','Category');

        'ActiveScriptEventConsumer'= @('Name','ScriptingEngine','ScriptFileName','ScriptText');

        'LogFileEventConsumer'     = @('Name','Filename','Text');

        'SMTPEventConsumer'        = @('Name','FromLine','ToLine','ReplyToLine','CcLine','BccLine','Subject','Message','SMTPServer')

    }

    if ($BindingPath -match '__FilterToConsumerBinding\.Consumer=".+\.')
    {

        $consumerType = $Matches[0].split('"')[1].split('.')[0]

        Remove-Variable Matches -Force

    } else {

        return 0

    }

    if ($Credentialed)
    {
    
        $creds = Get-Credential
    
    } elseif ($ProvideCreds) {
    
        $creds = $ProvideCreds
    
    }

    if ($BindingPath -match "$consumerType.Name=\\`".+\\`"")
    {

        $consumerName = $Matches[0].split('"')[1] -replace '.$'

        Remove-Variable Matches -Force

    } else {

        return 0

    }

    if ($BindingPath -match '__EventFilter\.Name=\\".+\\"')
    {

        $filterName = $Matches[0].split('"')[-2] -replace '.$'

        Remove-Variable Matches -Force

    } else {

        return 0

    }

    if ($credentialed -or $ProvideCreds)
    {

        $consumerResults = Get-WmiObject -Credential $creds -ComputerName $ComputerName -Namespace 'root/subscription' -Query "Select * from $consumerType where Name=`"$consumerName`"" | Select-Object -Property $ConsumerProperties[$consumerType]

        $filterResults = Get-WmiObject -Credential $creds  -ComputerName $ComputerName -Namespace 'root/subscription' -Query "Select * from __EventFilter where Name=`"$filterName`"" | Select-Object -Property @('Name','Query')

    } else {

        $consumerResults = Get-WmiObject -ComputerName $ComputerName -Namespace 'root/subscription' -Query "Select * from $consumerType where Name=`"$consumerName`"" | Select-Object -Property $ConsumerProperties[$consumerType]

        $filterResults = Get-WmiObject -ComputerName $ComputerName -Namespace 'root/subscription' -Query "Select * from __EventFilter where Name=`"$filterName`"" | Select-Object -Property @('Name','Query')

    }

    if ($consumerResults -and $filterResults)
    {

        return @($consumerResults, $filterResults)

    } else {

        return 0

    }

}

function Invoke-EnumerateAllWMIEventSubscriptions
{

    [CmdletBinding()]

    Param(

        [Parameter(Mandatory=$true)]

        [String[]]$ComputerNames,

        [Switch]$Credentialed,

        [System.Management.Automation.PSCredential]$ProvideCreds = $null

    )

    if ($Credentialed)
    {

        $creds = Get-Credential

    } elseif ($ProvideCreds) {

        $creds = $ProvideCreds

    }

    foreach ($computer in $ComputerNames)
    {
        if ($Credentialed -or $ProvideCreds)
        {

            $__Path = Get-WMIEventSubscriptions -ComputerNames $Computer -Type BindingPath -ProvideCreds $creds

        } else {

            $__Path = Get-WMIEventSubscriptions -ComputerNames $Computer -Type BindingPath

        }

        if ($__Path)
        {

            foreach ($binding in $__Path)
            {

                foreach ($values in $binding.values)
                {
                    foreach ($val in $values)
                    {
                        
                        Write-Output "[+]  HOST: $computer"

                        if ($Credentialed -or $ProvideCreds)
                        {

                            Invoke-ClarifyEventSubscription -ComputerName $computer -BindingPath $val -ProvideCreds $creds | Format-List

                        } else {

                            Invoke-ClarifyEventSubscription -ComputerName $computer -BindingPath $val | Format-List
                    
                        }
                    }

                }
            
            }
        
        }
    
    }

}

function Invoke-WMIHashSweep
{

    Param(

        [CmdletBinding()]

        [Parameter(Mandatory=$true)]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )
    if ($Credentialed)
    
    {

        $creds = Get-Credential

    }

    [System.Collections.Hashtable]$results = @{}

    foreach ($computer in $ComputerNames)
    {

        if ($Credentialed)
        {
            $str = ''

            $bindingPath = Get-WMIEventSubscriptions -Type BindingPath -ComputerNames $computer -ProvideCreds $creds

            $bindingPath.Values | % { $str += $_ }

            $hash = Invoke-HashString -Data $str

            $results[$computer] = $hash

        } else {

            $str = ''

            $bindingPath = (Get-WMIEventSubscriptions -Type BindingPath -ComputerNames $computer).values -join ''

            $bindingPath.Values | % { $str += $_ }

            $hash = Invoke-HashString -Data $str

            $results[$computer] = $hash

        }

    }

    return $results

}

function Get-ActiveHosts
{

    Param(

        [CmdletBinding()]

        [String]$Subnet,

        [Int]$Start,

        [Int]$End

    )

    for ($i = $Start; $i -le $End; $i++)
    {

        $CurrentHost = "$Subnet.$i"

        $ping = Test-Connection -ComputerName $CurrentHost -Count 1 -AsJob

    }

    Start-Sleep 5

    $totalLive = 0

    foreach ($job in Get-Job)
    {

        if ($job.jobstateinfo.state -ne 'Running')
        {

            $ping = Receive-Job -Job $job

            if ($ping.StatusCode -eq 0)
            {

                Write-Output $ping.ProtocolAddress

                $totalLive++

            }

        }

    }

    Write-Warning "Total Live Hosts: $totalLive"

}

function Get-RemoteProcessCount
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed)
    {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Class 'Win32_Process' -ComputerName $computer -Credential $creds
            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Class 'Win32_Process' -ComputerName $computer

            }

            foreach ($proc in $d)
            {

                $p = $proc.ExecutablePath

                if (-not $results[$p])
                {

                    $results[$p] = @()

                    $counts[$p] = 0

                }

                $results[$p] += $computer

                $counts[$p]++

            }

        }
    
    }

    foreach ($i in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {

        Write-Output "[+] Count: $($i.value), Executable: $($i.key)"

        $results[$i.key] -join ', '

        Write-Output "`n"

    }

    
    $ErrorActionPreference = $errorpref

    
}

function Get-RemoteServiceCount
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Class 'Win32_Service' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Class 'Win32_Service' -ComputerName $computer

            }

            foreach ($serv in $d)
            {

                $s = $serv.Name

                if (-not $results[$s])
                {

                    $results[$s] = @()

                    $counts[$s] = 0

                }

                $results[$s] += $computer

                $counts[$s]++

            }

        }
    
    }

    foreach ($i in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {

        Write-Output "[+] Count: $($i.value), Service Name: $($i.key)"

        $results[$i.key] -join ', '

        Write-Output "`n"

    }
    
    $ErrorActionPreference = $errorpref

}

function Get-HashSum
{
    Param(

        [CmdletBinding()]

        [String[]]$Filenames,

        [ValidateSet('MD5','SHA1','SHA256')]

        [String[]]$Algorithm = 'MD5'

    )

    [System.Collections.Hashtable]$results = @{}

    foreach ($file in $Filenames)
    {

        if (-not (Test-Path $file -PathType Leaf))
        {
            
            Write-Warning "File Doesn't Exist: $file"

            continue

        }

        $hasher = [Security.Cryptography.HashAlgorithm]::Create($Algorithm)

        $s = ([System.IO.StreamReader]$file).BaseStream

        $hash = [System.BitConverter]::ToString($hasher.ComputeHash($s))

        $results[$file] = $hash.replace('-','')

        Remove-Variable @('hasher','s','hash')

    }

    return $results | Format-List

}

function Get-PSExecs
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    $cultureInfo = New-Object System.Globalization.CultureInfo('en-US')

    [System.Collections.HashTable]$results = @{}

    if ($Credentialed)
    {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            Write-Output "[*] Checking Host: $computer"
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Query 'Select * from Win32_NtLogEvent where EventCode=7045' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Query 'Select * from Win32_NtLogEvent where EventCode=7045' -ComputerName $computer

            }

            foreach ($serviceInstall in $d)
            {

                $t = ([DateTime]::ParseExact($serviceInstall.TimeGenerated.split('.')[0],'yyyyMMddHHmmss',$cultureInfo))

                [string]$query = "Select * from Win32_NTLogEvent WHERE (TimeGenerated >= '$($t.AddSeconds(-2).ToString('yyyyMMdd HH:mm:ss'))' and TimeGenerated <= '$($t.AddSeconds(2).ToString('yyyyMMdd HH:mm:ss'))') and EventIdentifier=4624"

                if ($Credentialed)
                {

                    $logins = Get-WmiObject -Namespace 'root/cimv2' -Query $query -ComputerName $computer -Credential $creds

                } else {

                    $logins = Get-WmiObject -Namespace 'root/cimv2' -Query $query -ComputerName $computer

                }

                foreach ($login in $logins)
                {
                    Write-output "[!]   Possible PSExec Found, Host: $computer, Time: $t"
                    $msg = $login.message.split([System.Environment]::NewLine)
                    $fields = @('workstation name:',
                                'source network address:',
                                'source port:',
                                'account name:',
                                'account domain:',
                                'logon type:')
                                
                    foreach ($m in $msg.trim().tolower())
                    {
                        $fields | ForEach-Object { if ($m -match $_) { write-output "        $m" } }
                    }
                }
                

            }
            
            Write-Output ''

        }
    
    }
    
    $ErrorActionPreference = $errorpref

    
}

function Get-TZOffset
{
    Param(
        [string]$ComputerName,
        [System.Management.Automation.PSCredential]$Credentials
    )

    $result = 0

    if ($Credentials -ne $null)
    {
        $result = (Get-WmiObject -ComputerName $ComputerName -Class 'Win32_TimeZone' -Credential $Credentials).bias
    } else {
        $result = (Get-WmiObject -ComputerName $ComputerName -Class 'Win32_TimeZone').bias
    }

    return $result
}

function Get-ServiceInfo
{
    Param(
        [string[]]$ComputerNames,
        [string[]]$ServiceNames,
        [switch]$Credentialed
    )

    if ($Credentialed)
    {

        $creds = Get-Credential

    }

    $ServiceQuery = $ServiceNames -join "%' or Name LIKE '%"
    $ServiceQuery = "Select * From Win32_Service WHERE (Name LIKE '%$ServiceQuery%')"

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Query $ServiceQuery -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Query $ServiceQuery -ComputerName $computer

            }

            Write-Output "[+] Host: $computer"
            foreach ($svc in $d)
            {
                Write-Output "    Service Name:    $($svc.Name)"
                Write-Output "    Executable Path: $($svc.PathName)"
                Write-Output "    Status:          $($svc.State)"
                Write-Output ''
            }
        }
    }
}

function Get-ProcessInfo
{
    Param(
        [string[]]$ComputerNames,
        [string[]]$ProcessNames,
        [switch]$Credentialed
    )

    if ($Credentialed)
    {

        $creds = Get-Credential

    }

    $cultureInfo = New-Object System.Globalization.CultureInfo('en-US')
    $ProcessQuery = $ProcessNames -join "%' or ExecutablePath LIKE '%"
    $ProcessQuery = "Select * From Win32_Process WHERE (ExecutablePath LIKE '%$ProcessQuery%')"

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Query $ProcessQuery -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Query $ProcessQuery -ComputerName $computer

            }

            Write-Output "[+] Host: $computer"
            foreach ($proc in $d)
            {
                $dt = [DateTime]::ParseExact($proc.CreationDate.split('.')[0],'yyyyMMddHHmmss',$cultureInfo)
                Write-Output "    Process Name:    $($proc.Name)"
                Write-Output "    Parent PID:      $($proc.ParentProcessId)"
                Write-Output "    Process ID:      $($proc.ProcessId)"
                Write-Output "    Executable Path: $($proc.ExecutablePath)"
                Write-Output "    Commandline:     $($proc.CommandLine)"
                Write-Output "    Creation Time:   $($dt)"
                Write-Output "    User:            $($proc.GetOwner().User)"
                Write-Output ''
            }
        }
    }
}

function Get-ProcessInfoByPIDs
{
    Param(
        [string[]]$ComputerName,
        [string[]]$ProcessPIDs,
        [switch]$Credentialed
    )

    if ($Credentialed)
    {

        $creds = Get-Credential

    }

    $cultureInfo = New-Object System.Globalization.CultureInfo('en-US')
    $ProcessQuery = $ProcessPIDs -join ' or ProcessId='
    $ProcessQuery = "Select * From Win32_Process WHERE (ProcessId=$ProcessQuery)"


    if ((Test-Connection -Count 1 -ComputerName $ComputerName).StatusCode -eq 0)
    {
            
        if ($Credentialed)
        {

            $d = Get-WmiObject -Namespace 'root/cimv2' -Query $ProcessQuery -ComputerName $ComputerName -Credential $creds

        } else {

            $d = Get-WmiObject -Namespace 'root/cimv2' -Query $ProcessQuery -ComputerName $ComputerName

        }

        Write-Output "[+] Host: $ComputerName"
        foreach ($proc in $d)
        {
            $dt = [DateTime]::ParseExact($proc.CreationDate.split('.')[0],'yyyyMMddHHmmss',$cultureInfo)
            $dt = $dt.ToUniversalTime()
            Write-Output "    Process Name:    $($proc.Name)"
            Write-Output "    Parent PID:      $($proc.ParentProcessId)"
            Write-Output "    Process ID:      $($proc.ProcessId)"
            Write-Output "    Executable Path: $($proc.ExecutablePath)"
            Write-Output "    Commandline:     $($proc.CommandLine)"
            Write-Output "    Creation Time:   $($dt)"
            Write-Output "    User:            $($proc.GetOwner().User)"
            Write-Output ''
        }
    }
    
}

function Invoke-DecodeBase64
{
    Param(
        [string]$Base64String
    )
    [System.Text.Encoding]::Default.GetString([System.Convert]::FromBase64String($Base64String))
}

function Invoke-DecodeGZippedBase64
{
    Param(
        [string]$Base64String
    )
    $data = New-Object System.IO.MemoryStream(,[Convert]::FromBase64String($Base64String))
    $data = (New-Object IO.StreamReader(New-Object System.IO.Compression.GZipStream($data, [System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()

    return $data
}

function Get-RemoteDriverCount
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Class 'Win32_PnPSignedDriver' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -Class 'Win32_PnPSignedDriver' -ComputerName $computer

            }

            foreach ($serv in $d)
            {

                $s = $serv.DeviceName

                if (-not $results[$s])
                {

                    $results[$s] = @()

                    $counts[$s] = 0

                }

                $results[$s] += $computer

                $counts[$s]++

            }

        }
    
    }

    foreach ($i in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {

        Write-Output "[+] Count: $($i.value), Service Name: $($i.key)"

        $results[$i.key] -join ', '

        Write-Output "`n"

    }
    
    $ErrorActionPreference = $errorpref

}

function Invoke-PowershellSweep
{
    Param(
        [string[]]$ComputerNames,
        [switch]$Credentialed
    )

    $cultureInfo = New-Object System.Globalization.CultureInfo('en-US')
    $query = "Select * from Win32_Process where (ExecutablePath like '%powershell%' and CommandLine like '%exec%') and CommandLine like '%bypass%'"

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Query $query -ComputerName $computer -Credential $creds
            
            } else {
            
                $d = Get-WmiObject -Query $query -ComputerName $computer
            
            }

            if ($d.length -ne 0)
            {
                Write-Output "[+] Host: $computer"
                foreach ($proc in $d)
                {
                    $dt = [DateTime]::ParseExact($proc.CreationDate.split('.')[0],'yyyyMMddHHmmss',$cultureInfo)
                    $dt = $dt.ToUniversalTime()
                    Write-Output "    Process Name:    $($proc.Name)"
                    Write-Output "    Parent PID:      $($proc.ParentProcessId)"
                    Write-Output "    Process ID:      $($proc.ProcessId)"
                    Write-Output "    Executable Path: $($proc.PathName)"
                    Write-Output "    Commandline:     $($proc.CommandLine)"
                    Write-Output "    Creation Time:   $($dt)"
                    Write-Output ''
                }
            } else {
                Write-Output "[-] No Findings for Host: $computer"
            }
        }
    }
}

function Get-RemoteAVState
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/securitycenter2' -query 'Select * from AntiVirusProduct' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/securitycenter2' -query 'Select * from AntiVirusProduct' -ComputerName $computer

            }

            foreach ($serv in $d)
            {

                $s = $serv.productState

                if (-not $results[$s])
                {

                    $results[$s] = @()

                    $counts[$s] = 0

                }

                $results[$s] += $computer

                $counts[$s]++

            }

        }
    
    }

    foreach ($i in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {

        Write-Output "[+] Count: $($i.value), AV State: $($i.key)"

        $results[$i.key] -join ', '

        Write-Output "`n"

    }
    
    $ErrorActionPreference = $errorpref

}


function Get-RemoteAtJobs
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_ScheduledJob' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_ScheduledJob' -ComputerName $computer

            }

            foreach ($serv in $d)
            {

                $s = $serv.Name

                if (-not $results[$s])
                {

                    $results[$s] = @()

                    $counts[$s] = 0

                }

                $results[$s] += $computer

                $counts[$s]++

            }

        }
    
    }

    foreach ($i in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {

        Write-Output "[+] Count: $($i.value), At Job Name: $($i.key)"

        $results[$i.key] -join ', '

        Write-Output "`n"

    }
    
    $ErrorActionPreference = $errorpref

}


function Get-RemoteShares
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_Share' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_Share' -ComputerName $computer

            }

            foreach ($serv in $d)
            {

                $s = $serv.Path

                if (-not $results[$s])
                {

                    $results[$s] = @()

                    $counts[$s] = 0

                }

                $results[$s] += $computer

                $counts[$s]++

            }

        }
    
    }

    foreach ($i in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {

        Write-Output "[+] Count: $($i.value), Shares: $($i.key)"

        $results[$i.key] -join ', '

        Write-Output "`n"

    }
    
    $ErrorActionPreference = $errorpref

}

function Get-RemoteUsers
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_UserAccount' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_UserAccount' -ComputerName $computer

            }

            foreach ($serv in $d)
            {

                $s = $serv.Name

                if (-not $results[$s])
                {

                    $results[$s] = @()

                    $counts[$s] = 0

                }

                $results[$s] += $computer

                $counts[$s]++

            }

        }
    
    }

    foreach ($i in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {

        Write-Output "[+] Count: $($i.value), User: $($i.key)"

        $results[$i.key] -join ', '

        Write-Output "`n"

    }
    
    $ErrorActionPreference = $errorpref

}

function Get-RemoteStartupCommand
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_StartupCommand' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_StartupCommand' -ComputerName $computer

            }

            foreach ($serv in $d)
            {

                $s = $serv.Command

                if (-not $results[$s])
                {

                    $results[$s] = @()

                    $counts[$s] = 0

                }

                $results[$s] += $computer

                $counts[$s]++

            }

        }
    
    }

    foreach ($i in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {

        Write-Output "[+] Count: $($i.value), Startup Command: $($i.key)"

        $results[$i.key] -join ', '

        Write-Output "`n"

    }
    
    $ErrorActionPreference = $errorpref

}


function Get-RemoteHostNames
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_ComputerSystem' -ComputerName $computer -Credential $creds

            } else {

                $d = Get-WmiObject -Namespace 'root/cimv2' -query 'Select * from Win32_ComputerSystem' -ComputerName $computer

            }

            foreach ($serv in $d)
            {

                $s = $serv.Name

                Write-Output "[+] IP: $computer, Hostname: $s"

            }

        }
    
    }
    
    $ErrorActionPreference = $errorpref

}


function Get-RemoteRegistryPersistence
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}
    
    [System.Collections.Hashtable]$urls = @{}
    
    $HKLM = [UInt32]2147483650
    $HKCU = [UInt32]2147483649
    $RunKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {
                $res = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name EnumValues -ArgumentList @($HKLM, $RunKey) -ComputerName $computer -Credential $creds
                foreach ($instance in $res)
                {
                    foreach ($key in $instance.sNames)
                    {
                        $val = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetStringValue -ArgumentList @($HKLM, $RunKey, $key) -ComputerName $computer -Credential $creds
                        
                        if ([string]::IsNullOrEmpty($urls[$computer]))
                        {
                            $urls[$computer] = $val.sValue
                        } else {
                            $urls[$computer] += ",$($val.sValue)"
                        }
                    }
                }

            } else {

                $res = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name EnumValues -ArgumentList @($HKLM, $RunKey) -ComputerName $computer
                foreach ($instance in $res)
                {
                    foreach ($key in $instance.sNames)
                    {
                        $val = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetStringValue -ArgumentList @($HKLM, $RunKey, $key) -ComputerName $computer
                        
                        if ([string]::IsNullOrEmpty($urls[$computer]))
                        {
                            $urls[$computer] = $val.sValue
                        } else {
                            $urls[$computer] += ",$($val.sValue)"
                        }
                    }
                }

            }
        }
    }

    foreach ($computer in $urls.GetEnumerator())
    {
        $computername = $computer.key
        $urlsVisited = $urls[$computername].split(',')
        foreach ($url in $urlsVisited)
        {
            if (-not ($results.ContainsKey($url)))
            {
                $results[$url] = $computername
            } else {
                $results[$url] += ", $computername"
            }
        }
    }
    
    foreach ($dataPair in $results.GetEnumerator())
    {
        $counts[$dataPair.Key] = $dataPair.value.split(',').length
    }
    
    foreach ($dataPair in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {
        $url = $dataPair.key
        $computers = $results[$url]
        $instanceCount = $computers.length
        Write-Output "[+] Count: $($dataPair.value), Persistence: '$url'"
        Write-Output "    $computers"
        Write-Output ''
    }
    
    $ErrorActionPreference = $errorpref

}

function Get-RemoteTypedURLs
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}
    
    [System.Collections.Hashtable]$urls = @{}
    
    $HKLM = [UInt32] 2147483650
    $HKCU = [UInt32] 2147483649
    $UrlsKey = 'Software\Microsoft\Internet Explorer\TypedURLs'

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {
                $res = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name EnumValues -ArgumentList @($HKCU, $UrlsKey) -ComputerName $computer -Credential $creds
                foreach ($instance in $res)
                {
                    foreach ($key in $instance.sNames)
                    {
                        $val = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetStringValue -ArgumentList @($HKCU, $UrlsKey, $key) -ComputerName $computer -Credential $creds
                        
                        if ([string]::IsNullOrEmpty($urls[$computer]))
                        {
                            $urls[$computer] = $val.sValue
                        } else {
                            $urls[$computer] += ",$($val.sValue)"
                        }
                    }
                }

            } else {

                $res = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name EnumValues -ArgumentList @($HKCU, $UrlsKey) -ComputerName $computer
                foreach ($instance in $res)
                {
                    foreach ($key in $instance.sNames)
                    {
                        $val = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetStringValue -ArgumentList @($HKCU, $UrlsKey, $key) -ComputerName $computer
                        
                        if ([string]::IsNullOrEmpty($urls[$computer]))
                        {
                            $urls[$computer] = $val.sValue
                        } else {
                            $urls[$computer] += ",$($val.sValue)"
                        }
                    }
                }

            }
        }
    }
    
    foreach ($computer in $urls.GetEnumerator())
    {
        $computername = $computer.key
        $urlsVisited = $urls[$computername].split(',')
        foreach ($url in $urlsVisited)
        {
            if (-not ($results.ContainsKey($url)))
            {
                $results[$url] = $computername
            } else {
                $results[$url] += ", $computername"
            }
        }
    }
    
    foreach ($dataPair in $results.GetEnumerator())
    {
        $counts[$dataPair.Key] = $dataPair.value.split(',').length
    }
    
    foreach ($dataPair in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {
        $url = $dataPair.key
        $computers = $results[$url]
        $instanceCount = $computers.length
        Write-Output "[+] Count: $($dataPair.value), URL: '$url'"
        Write-Output "    $computers"
        Write-Output ''
    }

    $ErrorActionPreference = $errorpref

}

function Get-RemoteMappedDrives
{

    Param(

        [CMDletBinding()]

        [String[]]$ComputerNames,

        [Switch]$Credentialed

    )

    $errorpref = $ErrorActionPreference

    $ErrorActionPreference = 'SilentlyContinue'

    [System.Collections.Hashtable]$results = @{}

    [System.Collections.Hashtable]$counts = @{}
    
    [System.Collections.Hashtable]$urls = @{}
    
    $HKLM = [UInt32] 2147483650
    $HKCU = [UInt32] 2147483649
    $UrlsKey = 'software\Microsoft\Windows\CurrentVersion\explorer\Map Network Drive'

    if ($Credentialed) {

        $creds = Get-Credential

    }

    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {
                $res = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name EnumValues -ArgumentList @($HKCU, $UrlsKey) -ComputerName $computer -Credential $creds
                foreach ($instance in $res)
                {
                    foreach ($key in $instance.sNames)
                    {
                        $val = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetStringValue -ArgumentList @($HKCU, $UrlsKey, $key) -ComputerName $computer -Credential $creds
                        
                        if ([string]::IsNullOrEmpty($urls[$computer]))
                        {
                            $urls[$computer] = $val.sValue
                        } else {
                            $urls[$computer] += ",$($val.sValue)"
                        }
                    }
                }

            } else {

                $res = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name EnumValues -ArgumentList @($HKCU, $UrlsKey) -ComputerName $computer
                foreach ($instance in $res)
                {
                    foreach ($key in $instance.sNames)
                    {
                        $val = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetStringValue -ArgumentList @($HKCU, $UrlsKey, $key) -ComputerName $computer
                        
                        if ([string]::IsNullOrEmpty($urls[$computer]))
                        {
                            $urls[$computer] = $val.sValue
                        } else {
                            $urls[$computer] += ",$($val.sValue)"
                        }
                    }
                }

            }
        }
    }
    
    foreach ($computer in $urls.GetEnumerator())
    {
        $computername = $computer.key
        $urlsVisited = $urls[$computername].split(',')
        foreach ($url in $urlsVisited)
        {
            if (-not ($results.ContainsKey($url)))
            {
                $results[$url] = $computername
            } else {
                $results[$url] += ", $computername"
            }
        }
    }
    
    foreach ($dataPair in $results.GetEnumerator())
    {
        $counts[$dataPair.Key] = $dataPair.value.split(',').length
    }
    
    foreach ($dataPair in $counts.GetEnumerator() | Sort-Object Value -Descending)
    {
        $url = $dataPair.key
        $computers = $results[$url]
        $instanceCount = $computers.length
        Write-Output "[+] Count: $($dataPair.value), Mapped Drive: '$url'"
        Write-Output "    $computers"
        Write-Output ''
    }

    $ErrorActionPreference = $errorpref

}



function Set-RegistryScriptValue
{
    [CmdletBinding()]
    Param(
        [String]$ComputerName,
        [String]$Value,
        [System.Management.Automation.PSCredential]$Creds = $null,
        
        [ValidateSet('IN', 'OUT')]
        [Parameter(Mandatory=$true)]
        [String]$Type = 'IN'
    )
    
    $HKCU = [UInt32] 2147483649
    $ScriptKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\IRScripts'
    $ValueNameIn = 'SCRIPT_IN'
    $ValueNameOut = 'SCRIPT_OUT'
    $Value = ConvertTo-Base64 -Data $Value
    
    if (-not ($Creds -eq $null))
    {
        $created = (Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name CreateKey -ArgumentList @($HKCU, $ScriptKey) -Credential $Creds -ComputerName $ComputerName).ReturnValue
        
        if ($created -eq 0)
        {
            switch ($Type.ToLower())
            {
                'in' { $set = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name SetExpandedStringValue -ArgumentList @($HKCU, $ScriptKey, $Value, $ValueNameIn) -Credential $Creds -ComputerName $ComputerName }
                'out' { $set = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name SetExpandedStringValue -ArgumentList @($HKCU, $ScriptKey, $Value, $ValueNameOut) -Credential $Creds -ComputerName $ComputerName }
            }
        }
    }
    
    switch ($set.ReturnValue)
    {
        0       { $true }
        default { $false }
    }
    
}

function Get-RegistryScriptValue
{
    [CmdletBinding()]
    Param(
        [String]$ComputerName,
        [System.Management.Automation.PSCredential]$Creds = $null,
        
        [ValidateSet('IN', 'OUT')]
        [Parameter(Mandatory=$true)]
        [String]$Type = 'IN'
    )
    
    $HKCU = [UInt32] 2147483649
    $ScriptKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\IRScripts'
    $ValueNameIn = 'SCRIPT_IN'
    $ValueNameOut = 'SCRIPT_OUT'
    
    if (-not ($Creds -eq $null))
    {
        switch ($Type.ToLower())
        {
            'in' { $ScriptDefinition = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetExpandedStringValue -ArgumentList @($HKCU, $ScriptKey, $ValueNameIn) -ComputerName $ComputerName -Credential $Creds }
            'out' { $ScriptDefinition = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetExpandedStringValue -ArgumentList @($HKCU, $ScriptKey, $ValueNameOut) -ComputerName $ComputerName -Credential $Creds }
        }
        $results = ConvertFrom-Base64 -Data ($ScriptDefinition.sValue)
        $results
    }
}

function ConvertTo-Base64
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String]$Data
    )
    [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Data))
}

function ConvertFrom-Base64
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String]$Data
    )
    [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Data))
}

function Invoke-RemoteFileSearch
{
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String[]]$ComputerNames,
        
        [Parameter(Mandatory=$true)]
        [String]$FileName,
        
        [switch]$Credentialed = $false
    )
    
    $name = $FileName.split('.')[0]
    $ext = $FileName.split('.')[1]
    
    if ($Credentialed)
    {
        $creds = Get-Credential
    }
    
    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $files = Get-WmiObject -Query "Select * from CIM_DataFile where (FileName='$name' and Extension='$ext')" -ComputerName $computer -Credential $creds

            } else {
                
                $files = Get-WmiObject -Query "Select * from CIM_DataFile where (FileName='$name' and Extension='$ext')" -ComputerName $computer
                
            }
        }
        Write-Output "[+] Host: $computer"
        foreach ($file in $files)
        {
            Write-Output "  $($file.Name)"
        }
    }
}

function Invoke-ExecuteRegistryScript
{
    Param(
        [String]$ComputerName,
        [System.Management.Automation.PSCredential]$Creds = $null
    )

    if ($Creds -ne $null)
    {
        $executionScript = @"
`$
`$HKCU = [UInt32] 2147483649
`$ScriptKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\IRScripts'
`$ValueNameIn = 'SCRIPT_IN'
`$ScriptDefinition = (Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetExpandedStringValue -ArgumentList @(`$HKCU, `$ScriptKey, `$ValueNameIn)).sValue
`$ScriptText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(`$ScriptDefinition))
`$ScriptText > 'C:\users\dev\desktop\output.txt'
Invoke-Expression (`$ScriptText)
"@
        $encodedScript = ConvertTo-Base64 -Data $executionScript
        $command = "powershell.exe -NOPr -Windo HIDDEN -eNCo '$encodedScript'"
        $results = Invoke-WmiMethod -Namespace root/cimv2 -Class Win32_Process -Name Create -ArgumentList @("powershell.exe -NOPr -Windo HIDDEN -eNCo $encodedScript") -ComputerName $ComputerName -Credential $Creds
    }
    
    switch ($results.ReturnValue)
    {
        0       { $true }
        default { $false }
    }
}

function Invoke-RemoteEventSearch
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string[]]$ComputerNames,
        
        [Parameter(Mandatory=$true)]
        [int[]]$EventIDs,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile,
        
        [switch]$Credentialed=$false,
        
        [string]$MessageFilter
    )
    [System.Collections.ArrayList]$parameters = @()
    foreach ($ec in $EventIDs.GetEnumerator())
    {
        $parameters.Add("EventCode=$ec") | Out-Null
    }
    $q = 'Select * from Win32_NTLogEvent where'
    $c = "($($parameters -join ' or ')"
    $l = "(Logfile='$LogFile' and $c)"
    
    if ($MessageFilter)
    {
        $finalQuery = "$q $l and Message like '%$MessageFilter%')"
    } else {
        $finalQuery = "$q $l)"
    }
    Write-Warning "Query: $finalQuery"
    if ($Credentialed)
    {
        $creds = Get-Credential
    }
    
    foreach ($computer in $ComputerNames)
    {

        if ((Test-Connection -Count 1 -ComputerName $computer).StatusCode -eq 0)
        {
            
            if ($Credentialed)
            {

                $events = Get-WmiObject -Namespace 'root/cimv2' -Query $finalQuery -ComputerName $computer -Credential $creds

            } else {
                
                $events = Get-WmiObject -Namespace 'root/cimv2' -Query $finalQuery -ComputerName $computer
                
            }
        }
        $events
    }
}
