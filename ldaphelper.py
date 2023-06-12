#!/usr/bin/env python3

from ldap3 import Connection, Server, ANONYMOUS, SIMPLE, SYNC, ASYNC, KERBEROS
from ldap3 import Server, Connection, SAFE_SYNC, SASL, GSSAPI, DSA, SUBTREE, NTLM
from subprocess import Popen, PIPE
import logging
import re

logger = logging.getLogger('rSMBi')


class LDAPHelper():

    def __init__(self, options):
        self.options = options

    def kerberosAuth(self):
        userid = self.options.username
        password = self.options.password
        realm = (self.options.domain).upper()
        kinit = '/usr/bin/kinit'
        kinit_args = [kinit, '%s@%s' % (userid, realm)]
        kinit = Popen(kinit_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        kinit.communicate(input="{}\n".format(password).encode("utf-8"))
        kinit.wait()

    def retrieveComputerObjects(self):

        server = Server(self.options.dc_ip, get_info=DSA)
        authstring = self.options.username + \
            '@' + (self.options.domain).upper()

        try:
            conn = Connection(server, authstring, client_strategy=SAFE_SYNC,
                              auto_bind=True, authentication=SASL, sasl_mechanism=GSSAPI)

        except Exception as e:
            logger.error("exception in LDAP Connection")
            logger.error(e)

        dn = server.info.other["defaultNamingContext"][0]

        # status, result, response, _ = conn.search(dn, '(objectClass=Computer)', attributes=['dNSHostName'], paged_size=2000)
        status, result, response, _ = conn.search(
            dn, '(&(objectCategory=Computer)(name=*))', search_scope=SUBTREE, attributes=['dNSHostName'], paged_size=500)

        computerObjectsList = []
        total_entries = len(response)
        for co in response:
            try:
                computerObjectsList.append(
                    (co['attributes']['dNSHostName'])[0])
                # print ((co['attributes']['dNSHostName'])[0])
            except Exception as e:
                logger.warning("Error retrieving dNSHostName for ")
                logger.warning(co)

        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        while cookie:
            status, result, response, _ = conn.search(
                dn, '(&(objectCategory=Computer)(name=*))', search_scope=SUBTREE, attributes=['dNSHostName'], paged_size=500, paged_cookie=cookie)
            total_entries += len(response)
            for co in response:
                try:
                    computerObjectsList.append(
                        (co['attributes']['dNSHostName'])[0])
                except Exception as e:
                    logger.warning("Error retrieving dNSHostName for ")
                    logger.warning(co)
            cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        logger.info("Retrieved computer objects: ")
        logger.info(total_entries)
        return computerObjectsList

    def retrieveComputerObjectsNTLM(self):

        server = Server(self.options.dc_ip, get_info=DSA)
        authstring = self.options.domain+"\\"+self.options.username

        try:
            conn = Connection(server, authstring, password=self.options.password,
                              client_strategy=SAFE_SYNC, auto_bind=True, authentication=NTLM)

        except Exception as e:
            logger.error("exception in LDAP Connection [NTLM]")
            logger.error(e)

        dn = server.info.other["defaultNamingContext"][0]

        status, result, response, _ = conn.search(
            dn, '(&(objectCategory=Computer)(name=*))', search_scope=SUBTREE, attributes=['dNSHostName'], paged_size=500)

        computerObjectsList = []
        total_entries = len(response)
        domain = ""
        for co in response:
            try:
                computerObjectsList.append(
                    (co['attributes']['dNSHostName'])[0])
                # print ((co['attributes']['dNSHostName'])[0])
            except Exception as e:
                try:
                    x = re.findall('DC=(?<==)(.*?)(?=(,|$))', co['dn'])
                    for domainsub in x:
                        domain += (domainsub[0]) + '.'

                    computerObjectsList.append(((co['dn']).split(',')[0]).split(
                        '=')[1] + '.' + domain[:len(domain)-1])
                    # print(((co['dn']).split(',')[0]).split(
                    #    '=')[1] + '.' + domain[:len(domain)-1])
                except Exception as e:
                    logger.warning("Error retrieving dNSHostName for ")
                    logger.warning(co)
            domain = ""

        cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        while cookie:
            status, result, response, _ = conn.search(
                dn, '(&(objectCategory=Computer)(name=*))', search_scope=SUBTREE, attributes=['dNSHostName'], paged_size=500, paged_cookie=cookie)
            total_entries += len(response)
            for co in response:
                try:
                    computerObjectsList.append(
                        (co['attributes']['dNSHostName'])[0])
                except Exception as e:
                    try:
                        x = re.findall('DC=(?<==)(.*?)(?=(,|$))', co['dn'])
                        for domainsub in x:
                            domain += (domainsub[0]) + '.'

                        computerObjectsList.append(((co['dn']).split(',')[0]).split(
                            '=')[1] + '.' + domain[:len(domain)-1])
                        # print(((co['dn']).split(',')[0]).split(
                        #    '=')[1] + '.' + domain[:len(domain)-1])
                    except Exception as e:
                        logger.warning("Error retrieving dNSHostName for ")
                        logger.warning(co)
                domain = ""
            cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        logger.info("Retrieved computer objects: ")
        logger.info(total_entries)
        return computerObjectsList
