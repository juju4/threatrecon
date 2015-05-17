#!/usr/bin/python
## basic script to query threatrecon
##
## NEED: threatrecon
## in: ip list as stdin or one ip argument
## out: input data; json virustotal output

import sys, os, time, re
import traceback
## https://github.com/dechko/threatrecon/
## (not using requests ... no cache)
import socket
import json
import threatrecon as tr

import logging
#logging.basicConfig(format="%(filename)s:%(funcName)s:%(message)s", filename='debug.log',level=logging.DEBUG)
logging.basicConfig(format="%(filename)s:%(funcName)s:%(message)s", level=logging.DEBUG, stream=sys.stderr)
#logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

## https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
logging.captureWarnings(True)

w_network = 1
THREATRECON_LIMIT = 0
## Public API: 4 req/min
THREATRECON_KEY = '344eabf20583a2e0bde6e0cde7ee8feb'
TR_COUNT = 0

## if -2 = Exhausted Plan Limit
def threatrecon_data(domain, trkey=THREATRECON_KEY, trlimit=THREATRECON_LIMIT):
    if w_network == 1:
	global TR_COUNT
        try:
            	logger.debug("search: " + domain)
                domain = re.sub(r'^www\.', '', domain)
                domain = re.sub(r':\d+$', '', str(domain))
                trret = tr.query.raw_query_threat_recon_json(domain, trkey, enable_cache=True, cache_expire_after=259200)
            	logger.debug("result: " + str(trret))
		if tr.tr_last_cache_call != domain:
		    TR_COUNT +=1
                return trret
        except Exception, e:
            return "Threatrecon: error " + str(e)
    else:
        return "Network call disabled"

## either take stdin (one or multiple lines), either one argument
def main():
    global TR_COUNT
    try:
	print (len(sys.argv))
        if len(sys.argv) == 1:
            logger.debug("input as stdin")
            for line in sys.stdin:
                ## every 4req, sleep 1min to respect limitation
## FIXME! don't count in sleep limit the one pulled from cache...
                if TR_COUNT != 0 and TR_COUNT % 4 == 0:
                    logger.debug("sleeping a bit...")
                    time.sleep(60)
                logging.debug("input line: " + line.strip())
                print line.strip() + ';' + str(threatrecon_data(line.strip()))
        elif len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
            logger.debug("input as file: " + sys.argv[1])
            with open(sys.argv[1], "r") as lines:
                for line in lines:
                    ## every 4req, sleep 1min to respect limitation
                    if TR_COUNT != 0 and TR_COUNT % 4 == 0:
                        logger.debug("sleeping a bit...")
                        time.sleep(60)
                    logging.debug("input line: " + line.strip())
                    print line.strip() + ';' + str(threatrecon_data(line.strip()))
        elif len(sys.argv) > 1:
            logger.debug("input as argument: " + sys.argv[1])
            print threatrecon_data(sys.argv[1])
        logger.debug("ending")
    
    except KeyboardInterrupt:
        print 'Goodbye Cruel World...'
        sys.exit(0)
    except Exception, error:
        traceback.print_exc()
        print '(Exception):, %s' % (str(error))
        sys.exit(1)


if __name__ == '__main__':
    main()
