# ioc-enrichment
`rf_enrich.py` will query the Recorded Future API for enrichments to IP adressess (v4 and v6), supported hashes and internet domain names.

It accepts both a new-line separated file of indicators (using the `-f` toggle) and a single indicator (by just passing it as the first argument.)

In order for Recorded Future to be able to validate your requests you either need set the envirnoment variable `RECFUT_TOKEN` to your token, or pass the token along with each script invocation using the `-t <token>` flag.

Running `python rf_enrich.py --help` will provide a description of the different options available.

An example invocation (for a file containing a list of internet domain names):
```
$ python rf_enrich.py -t <token> -f alldomains.txt > enriched_domains.json
```
and it prints the following to stderr:
```
Enriching 183 IOC(s)...
   Processing idn : behesjusrat.com... Done.
   Processing idn : aningutterbut.com... Done.
   [...]
```
and the ouput to stdout is a JSON map between input and enrichment:
```
{
    "behesjusrat.com": {
        [...]
    },
    [...]
}
```
If no enrichment is available the output enrichment will be `No enrichment available.`
