<div class="documentation_overview">
	<h1 class="doc-title">IPQualityScore IP Address Reputation &amp; Proxy Detection Rust DB Reader</h1>
	<div class="spacing-10"></div>
	<h2 class="text-bold headerHR" style="font-size: 1.5em;">Flat File Version 1.0</h2>
	<div class="spacing-10"></div>
	<p>
        Our flat file proxy detection database allows you to lookup important details about any IP address using a straight forward library. Simply install the reader, download a database, and instantly check IP addresses against our large volume of data.
    </p>
    <a href="https://www.ipqualityscore.com/documentation/ip-reputation-database/rust" target="_blank">Click here to see the full Rust IPQualityScore flat file database documentation</a> or <a href="https://www.ipqualityscore.com/proxy-detection-database">click here for a more in depth explanation of what our proxy detection database does</a>. <a href="https://crates.io/crates/ipqs_db_reader" target="_blank">The library crate listing and Cargo-generated docs can be found here</a>.
    <h6 class="text-bold headerHR">Installation</h6>
	<div class="spacing-10"></div>
	<p>
        To install, simply run the following Cargo command in your project directory:  
    </p>
    <div class="row">
		<div class="col-md-12 xsmcode">
			<pre class="highlight markdown"><code>
cargo add ipqs_db_reader
			</code></pre>
        </div>
    </div>
    <h6 class="text-bold headerHR">Usage</h6>
	<div class="spacing-10"></div>
	<p>
        Using our flat file database system to lookup an IP address is simple:
    </p>
    <div class="row">
		<div class="col-md-12 lgcode">
            <pre class="highlight markdown"><code>
let ip: IpAddr = IpAddr::V4(Ipv4Addr::from_str("8.8.0.0").unwrap());

let mut path_buf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
path_buf.push("resources/IPQualityScore-IP-Reputation-Database-IPv4.ipqs");

let mut reader = FileReader::open(&path_buf)?;
let record = reader.fetch(&ip)?;

if let Some(is_proxy) = record.is_proxy() {
    if is_proxy {
        println!("{} is a proxy!", ip);
    }
}

println!("Connection type: {}", record.connection_type());
if let Some(fraud_score) = record.fraud_score(Strictness::Zero) {
    println!("Fraud Score (Strictness 0): {:#?}", fraud_score);
}

// Record implements fmt::Display
println!("{}", record);

// Record implements serde::Serialization
#[cfg(feature = "json")]
{
    let serialized = serde_json::to_string_pretty(&record)?;
    println!("{}", serialized);
}

// Record implements Clone
let _ = record;
            </code></pre>
        </div>
    </div>
    <h6 class="text-bold headerHR">Usage Notes</h6>
	<div class="spacing-10"></div>
	<ul>
        <li>Each database only holds either IPv4 or IPv6 data. Therefore you may need two instances of the reader available depending on your use case.</li>
        <li>Make sure to include the release option <code>cargo build --release</code> when compiling, as this will greatly speed up searches.</li>
        <li>The feature to serialize the Record struct into JSON is enabled by default. This feature requires <code>serde</code> and <code>serde_json</code> as dependencies. If you do not need to serialize results and would like to build with no external dependencies (other than the Rust Standard Library), disable default features.
        <pre><code>
[dependencies]
ipqs_db_reader = { version = "1.0.0", default-features = false, }
        </code></pre>
</li>
    </ul>
    <h6 class="text-bold headerHR">Record Struct Methods</h6>
	<div class="spacing-10"></div>
	<p>
        Depending on which database file you receive, some of these fields may be unavailable. If the field in question is unavailable in your database,
        the associated method will return Option::None.
    </p>
    <div class="row">
		<div class="col-md-12">
			<table class="table table-legend custom-tablelegend">
				<thead>
					<tr>
                        <th>Implementations</th>
						<th>Description</th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td><code>pub fn is_proxy(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>Is this IP address suspected to be a proxy? (SOCKS, Elite, Anonymous, VPN, Tor, etc.)</td>
					</tr>
                    <tr>
                        <td><code>pub fn is_vpn(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>Is this IP suspected of being a VPN connection? This can include data center ranges which can become active VPNs at any time. The "proxy" status will always be true when this value is true.</td>
					</tr>
                    <tr>
						<td><code>pub fn is_tor(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>Is this IP suspected of being a TOR connection? This can include previously active TOR nodes and exits which can become active TOR exits at any time. The "proxy" status will always be true when this value is true.</td>
					</tr>
                    <tr>
						<td><code>pub fn is_crawler(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>Is this IP associated with being a confirmed crawler from a mainstream search engine such as Googlebot, Bingbot, Yandex, etc. based on hostname or IP address verification.</td>
					</tr>
                    <tr>
						<td><code>pub fn is_bot(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>Indicates if bots or non-human traffic has recently used this IP address to engage in automated fraudulent behavior. Provides stronger confidence that the IP address is suspicious.</td>
					</tr>
                    <tr>
						<td><code>pub fn recent_abuse(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>This value will indicate if there has been any recently verified abuse across our network for this IP address. Abuse could be a confirmed chargeback, compromised device, fake app install, or similar malicious behavior within the past few days.</td>
					</tr>
                    <tr>
						<td><code>pub fn is_blacklisted(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>This value will indicate if the IP has been blacklisted by any 3rd party agency for spam, abuse or fraud.</td>
					</tr>
                    <tr>
						<td><code>pub fn is_private(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>This value will indicate if the IP is a private, nonrouteable IP address.</td>
					</tr>
                    <tr>
						<td><code>pub fn is_mobile(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>This value will indicate if the IP is likely owned by a mobile carrier.</td>
					</tr>
                    <tr>
						<td><code>pub fn has_open_ports(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>This value will indicate if the IP has recently had open (listening) ports.</td>
					</tr>
                    <tr>
						<td><code>pub fn is_hosting_provider(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>This value will indicate if the IP is likely owned by a hosting provider or is leased to a hosting company.</td>
					</tr>
                    <tr>
						<td><code>pub fn active_vpn(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>Identifies active VPN connections used by popular VPN services and private VPN servers.</td>
					</tr>
                    <tr>
						<td><code>pub fn active_tor(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>Identifies active TOR exits on the TOR network.</td>
					</tr>
                    <tr>
						<td><code>pub fn public_access_point(&amp;self) -&gt; Option&lt;bool&gt;</code></td>
						<td>Indicates if this IP is likely to be a public access point such as a coffee shop, college or library.</td>
					</tr>
                    <tr>
						<td><code>pub fn connection_type(&amp;self) -&gt; &amp;str</code></td>
						<td>
                            <p>
                                The suspected type of connection for this IP address. Returns one of: "Residential", "Mobile", "Corporate", "Data Center", "Education", or "Unknown".
                            </p>
                        </td>
					</tr>
                    <tr>
						<td><code>pub fn abuse_velocity(&amp;self) -&gt; &amp;str</code></td>
						<td>
                            <p>
                                How frequently the IP address is engaging in abuse across the IPQS threat network. Values can be "high", "medium", "low", or "none".
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn country(&amp;self) -&gt; Option&lt;&amp;str&gt;</code></td>
						<td>
                            <p>
                                Two character country code of IP address or "N/A" if unknown.
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn city(&amp;self) -&gt; Option&lt;&amp;str&gt;</code></td>
						<td>
                            <p>
                                City of IP address if available or "N/A" if unknown.
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn isp(&amp;self) -&gt; Option&lt;&amp;str&gt;</code></td>
						<td>
                            <p>
                                ISP if one is known. Otherwise "N/A".
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn region(&amp;self) -&gt; Option&lt;&amp;str&gt;</code></td>
						<td>
                            <p>
                                Region (or State) if one is known. Otherwise "N/A".
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn organization(&amp;self) -&gt; Option&lt;&amp;str&gt;</code></td>
						<td>
                            <p>
                                Organization if one is known. Can be parent company or sub company of the listed ISP. Otherwise "N/A".
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn asn(&amp;self) -&gt; Option&lt;u64&gt;</code></td>
						<td>
                            <p>
                                Autonomous System Number if one is known. Zero if nonexistent.
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn timezone(&amp;self) -&gt; Option&lt;&amp;str&gt;</code></td>
						<td>
                            <p>
                                Timezone of IP address if available or "N/A" if unknown.
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn latitude(&amp;self) -&gt; Option&lt;f32&gt;</code></td>
						<td>
                            <p>
                                Latitude of IP address if available or 0.00 if unknown.
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn longitude(&amp;self) -&gt; Option&lt;f32&gt;</code></td>
						<td>
                            <p>
                                Longitude of IP address if available or 0.00 if unknown.
                            </p>
                        </td>
                    </tr>
                    <tr>
						<td><code>pub fn fraud_score(&amp;self, strictness: Strictness) -&gt; Option&lt;u32&gt;</code></td>
						<td>
                            <p>
                                Returns the fraud score associated with the IP address corresponding to the given strictness. Strictness can be one of: Strictness::{Zero, One, Two, Three}. Some databases may contain only 1 entry, others all 4. We recommend starting at Strictness::Zero, the lowest strictness setting, and increasing to Strictness::One depending on your levels of fraud. Levels greater than Strictness::One have a very high risk of false-positives. If a fraud score corresponding to the given strictness does not exist, this method will return Option::None.
                            </p>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>