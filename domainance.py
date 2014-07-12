# -*- coding: utf-8 -*-
"""
Created on Sat Jul 12 04:52:50 2014

@author: aaron
"""

import pythonwhois
import socket
import time

tld_data={
   'ch':{'hammer_delay_ms':1000,'purchasable_string':None},
   'sh':{'whois_works':True,
         'hammer_delay_ms':None,
         'purchasable_string':'available'},
   'is':{'whois_host':'whois.isnic.is',
         'whois_works':False,
         'hammer_delay_ms':None,
         'purchasable_string':'No entries found',
         'notes':
             """
             Access was denied after 43 requests. http://www.isnic.is had a
             captcha. Results say to use port 4343 for domain existence.
             """
        },
}

with open('/usr/share/dict/words') as wordlist:
    words=wordlist.readlines()

def find_words_with_suffix(suffix='sh'):
    res=[]
    # words in the list end with the newline character \n
    suffix=suffix + '\n'
    for word in words:
        if len(word) < 8 and word.endswith(suffix):
            #let's get rid of the newlines now
            res.append(word.strip('\n'))
    return res

def run_whois_on_tlds(tlds):
    purchaseable={}
    for tld in tlds:
        
        words=find_words_with_suffix(tld)
        whois_results=run_whois_on_domains(words, tld)
        purchaseable[tld]=list_purchasable(whois_results, tld)

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

def list_purchasable_tld(words, tld):
    purchasable=[]
    for word in words:
        domain=word[:-len(tld)]+'.'+tld
        if is_purchasable(domain, tld):
            purchasable.append(domain)
    return purchasable

def is_purchasable(domain, tld):
    if tld_data[tld]['whois_works']:
        try:
            whois_result=pythonwhois.get_whois(domain)
        except:
            print "failed on " + domain
            return None
        if tld_data[tld]['purchasable_string'] in whois_result['raw'][0]:
            return True
        
    if tld == 'sh':
        if not whois_result.has_key('status'):
            if 'available' in whois_result['raw'][0]:
                return True
        else:
            return False
    
    if tld == 'is':
        s = socket.socket()
        s.connect((tld_data[tld]['whois_host'],4343))
        s.sendall(domain+'\r\n')
        data = recv_timeout(s)
        s.close()
        if tld_data[tld]['purchasable_string'] in data:
            return True
    
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
    