# webanalyzer
detect active vulnerablity and finding hidden directories 
usage 
pip install requests colorama

# Full scan
python3 webanalyzer.py https://testphp.vulnweb.com

# Skip slow modules for quick recon
python3 webanalyzer.py https://example.com --skip-nvd --skip-active

# Only vuln scan, no dir/subdomain discovery
python3 webanalyzer.py https://example.com --skip-dirs --skip-subs --modules sqli xss

# Add custom wordlists + save report
python3 webanalyzer.py https://example.com --extra-dirs secret internal --extra-subs dev api --output report.json
