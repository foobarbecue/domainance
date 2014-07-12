# -*- coding: utf-8 -*-
"""
Created on Sat Jul 12 04:52:50 2014

@author: aaron
"""

import pythonwhois
import socket
import time

tld_data={
   'ch':{'whois_works':True,
         'hammer_delay_ms':1000,
         'purchasable_string':'We do not have an entry in our database matching your query.',
         'notes':'Had this one time out on me. Not sure what the hammer rules are, though.'},
   'sh':{'whois_works':True,
         'purchasable_string':'available'},
   'is':{'whois_host':'whois.isnic.is',
         'whois_works':False,
         'purchasable_string':'No entries found',
         'notes':
             """
             Access was denied after 43 requests. http://www.isnic.is had a
             captcha. Results say to use port 4343 for domain existence.
             """
        },
    'am':{
        'purchasable_string':'No match',
        'whois_works':True
    },
    'ac':{
        'whois_works':True,
        'purchasable_string':'available for purchase',
    },
    'ee':{
        'whois_works':True,
        'purchasable_string':'no entries found',
    },
    'il':{
        'whois_works':True,
        'blocked_string':'DENIED',
        'hammer_delay_ms':1000,
        'purchasable_string':'No data was found',
        'notes':'hammer detection triggers with access to whois service at whois.isoc.org.il was **DENIED**'
    },
    'in':{
        'whois_works':True,
        'blocked_string':'WHOIS QUERY RATE LIMIT EXCEEDED.  PLEASE WAIT AND TRY AGAIN.',
        'purchasable_string':'NOT FOUND',
    },    
    'ga':{
        'whois_works':False,
        'notes':'WHOIS server not found.',
    }
}

class BlockedException(Exception):
    pass

def find_words_with_suffix(suffix='sh'):
    with open('/usr/share/dict/words') as wordlist:
        words=wordlist.readlines()

    res=[]
    # words in the list end with the newline character \n
    suffix=suffix + '\n'
    for word in words:
        if len(word) < 8 and word.endswith(suffix):
            #let's get rid of the newlines now
            res.append(word.strip('\n'))
    return res

def run_whois_on_domains(words, tld='sh'):
    whois_results={}
    for word in words:
        domain=word[:-len(tld)]+'.'+tld
        print "checking " + domain
        try:
            whois_result=pythonwhois.get_whois(domain)
        except:
            print "failed on " + domain
            continue
        whois_results[domain]=whois_result            
    return whois_results

def list_purchasable_dnhacks(tlds):
    purchasable=[]
    for tld in tlds:
        try:
            words = find_words_with_suffix(tld)
            purchasable.append(list_purchasable_tld(words, tld))
        except BlockedException:
            print "blocked by " + tld
            continue
    return purchasable

def list_purchasable_tld(words, tld):
    purchasable=[]
    for word in words:
        domain=word[:-len(tld)]+'.'+tld
        if is_purchasable(domain, tld):
            print domain + ' is available'
            purchasable.append(domain)
        else:
            print domain + ' is not available'                        
    return purchasable

def is_purchasable(domain, tld):
    if tld_data[tld]['whois_works']:
        if tld_data[tld].has_key('hammer_delay_ms'):
            time.sleep(tld_data[tld]['hammer_delay_ms']/1000.0)
        try:
            whois_result=pythonwhois.get_whois(domain)
        except:
            print "failed on " + domain
            return None
        if tld_data.has_key('blocked_string') and tld_data[tld]['blocked_string'] in whois_result['raw'][0]:
            raise BlockedException
        return tld_data[tld]['purchasable_string'] in whois_result['raw'][0]

    else:
        if tld == 'sh':
            return 'available' in whois_result['raw'][0]
        
        if tld == 'is':
            s = socket.socket()
            s.connect((tld_data[tld]['whois_host'],4343))
            s.sendall(domain+'\r\n')
            data = recv_timeout(s)
            s.close()
            return tld_data[tld]['purchasable_string'] in data
    
def print_status_of_domains(whois_results):
    for k, v in whois_results.items():
        try:
            print '%s has status %s' % (k, v['status'])
        except KeyError:
            print 'no status for '+ k
    
    for k, v in whois_results.items():
        if not v.has_key('status'):
            print '%s has raw %s' % (k, v['raw'])
        
        if 'available' in v['raw'][0]:
            print k

    if not v.has_key('status'):
        if 'available' in v['raw'][0]:
            print k

# from http://www.binarytides.com/receive-full-data-with-the-recv-socket-function-in-python/
def recv_timeout(the_socket,timeout=2):
    #make socket non blocking
    the_socket.setblocking(0)
     
    #total data partwise in an array
    total_data=[];
    data='';
     
    #beginning time
    begin=time.time()
    while 1:
        #if you got some data, then break after timeout
        if total_data and time.time()-begin > timeout:
            break
         
        #if you got no data at all, wait a little longer, twice the timeout
        elif time.time()-begin > timeout*2:
            break
         
        #recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                #change the beginning time for measurement
                begin = time.time()
            else:
                #sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass
     
    #join all parts to make final string
    return ''.join(total_data)