#!/usr/bin/env python
# site shield security group master
# 28/11/2016 version 1.0 by Jackie Chen

import os
import sys
import json
import argparse
import logging
import siteshield
import securitygroup

base_url = os.environ['SS_BASEURL']
client_token = os.environ['SS_CLIENTTOKEN']
client_secret = os.environ['SS_CLIENTSECRET']
access_token = os.environ['SS_ACCESSTOKEN']
ss_client = siteshield.Client(base_url, client_token, client_secret, access_token)

siteshield_map_ids = ['1000', '1001']
siteshield_sg_groups = ['sg-672b3203', 'sg-792b321d', 'sg-552b3231', 'sg-262b3242']
trusted_cidr = ['51.51.51.51/32', '52.52.52.52/32']

current_cidr = list()
proposed_cidr = list()
new_cidr = list()
staging_cidr = list()
configed_cidr = list()
missed_cidr = list()
obsolete_cidr = list()
total_empty_slots = 0


logger = logging.getLogger('__name__')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
handler = logging.FileHandler('log')
handler.setFormatter(formatter)
logger.addHandler(handler)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter_console = logging.Formatter('%(message)s')
console.setFormatter(formatter_console)
logging.getLogger('__name__').addHandler(console)


def get_map_info():
    logger.info("Checking, please wait...")
    ss_maps = json.loads(ss_client.list_maps())
    logger.info('There are ' + str(len(ss_maps['siteShieldMaps'])) + ' site shield maps.')
    for ss_map in ss_maps['siteShieldMaps']:
        logger.info('Name:' + ss_map['ruleName'] + ' ID:' + str(ss_map['id']))


def get_map_cidr(id, cidr_type):
    return json.loads(ss_client.get_map(id))[cidr_type]


def get_type_cidr(ids, cidr_type):
    type_cidr_ = list()
    for id in ids:
        for ip in get_map_cidr(id, cidr_type):
            type_cidr_.append(ip)
    return list(set(type_cidr_))


def ack_proposed_cidr(ids):
    logger.info('\n------------Acknowledgement------------')
    if len(missed_cidr) > 0:
        logger.warn('New cidr need to be added first!')
        return False    
    ack_results = list()
    for id in ids:
        if len(get_map_cidr(id, 'proposedCidrs')) > 0:
            logger.info('Acknowledging map ' + id)
            ack_results.append(ss_client.ack_map(id))
    if len(ack_results) > 0:
        for result in ack_results:
            logger.info(str(result))
            return True
    logger.info('Nothing needs to be acknowledged.')
    return False


def get_staging_cidr(filename):
    staging_cidr_ = list()
    with open(filename) as f:
        for line in f:
            if not line.strip():
                continue
            else:
                staging_cidr_.append(line.replace('\n', ''))
    return list(set(staging_cidr_))


def get_ingress_cidr(client):
    ingress_cidr_ = list()
    for rule in client.show_ingress():
        for ip in rule['IpRanges']:
            ingress_cidr_.append(ip['CidrIp'])
    return ingress_cidr_


def find_ingress_cidr(clients, cidr):
    for client in clients:
        if get_ingress_cidr(securitygroup.Client(client)).count(cidr) > 0:
            logger.info(cidr + ' is found in ' + client)
            return client
    logger.error('Could not find ' + cidr)
    return False


def add_ingress(client, cidr):
    logger.info('- Adding cidr: ' + cidr + ' to ' + client)
    try:
        logger.info(securitygroup.Client(client).add_ingress(IpProtocol='tcp', FromPort=80, ToPort=443, CidrIp=cidr))
    except:
        logger.error("Unexpected error: " + str(sys.exc_info()[1]))


def remove_ingress(client, cidr):
    logger.info('- Removing obsolete cidr: ' + cidr + ' from ' + client)
    try:
        logger.info(securitygroup.Client(client).remove_ingress(IpProtocol='tcp', FromPort=80, ToPort=443, CidrIp=cidr))
    except:
        logger.error("Unexpected error: " + str(sys.exc_info()[1]))


def get_empty_slots(client):
    empty_slots_ = 50 - len(get_ingress_cidr(client))
    return empty_slots_


def find_empty_slots(clients):
    for client in clients:
        empty_slot_ = get_empty_slots(securitygroup.Client(client))
        if empty_slot_ > 0:
            logger.debug(client + ' has ' + str(empty_slot_) + ' empty slots')
            return client
    logger.error('There is no empty slot')
    sys.exit()


def get_total_empty_slots(clients):
    total_empty_slots_ = 0
    for client in clients:
        total_empty_slots_ += get_empty_slots(securitygroup.Client(client))
    return total_empty_slots_


def get_configed_cidr(clients):
    configed_cidr_ = list()
    for client in clients:
        for ip in get_ingress_cidr(securitygroup.Client(client)):
            configed_cidr_.append(ip)
    return configed_cidr_


def check_missed_cidr():
    missed_cidr_ = list()
    missed_prod_cidr_ = list()
    missed_staging_cidr_ = list()

    for ip in current_cidr:
        logger.debug('Checking production {0}/{1}: {2} matches {3} times '\
            .format(str(current_cidr.index(ip) + 1), str(len(current_cidr)), ip, str(configed_cidr.count(ip))))
        if configed_cidr.count(ip) == 0:
            missed_prod_cidr_.append(ip)
            missed_cidr_.append(ip)

    for ip in staging_cidr:
        logger.debug('Checking staging {0}/{1}: {2} matches {3} times '\
            .format(str(staging_cidr.index(ip) + 1), str(len(staging_cidr)), ip, str(configed_cidr).count(ip)))
        if configed_cidr.count(ip) == 0:
            missed_staging_cidr_.append(ip)
            missed_cidr_.append(ip)

    logger.info('Missed production cidr number: ' + str(len(missed_prod_cidr_)))
    for ip in missed_prod_cidr_:
        logger.info(ip)
    logger.info('Missed staging cidr number: ' + str(len(missed_staging_cidr_)))
    for ip in missed_staging_cidr_:
        logger.info(ip)
    return missed_cidr_


def check_obsolete_cidr():
    obsolete_cidr_ = list()
    for ip in configed_cidr:
        logger.debug('Checking {0}/{1}: {2} matches {3} times'\
            .format(str(configed_cidr.index(ip) + 1), str(len(configed_cidr)), ip,
                    str(current_cidr.count(ip) + proposed_cidr.count(ip) + staging_cidr.count(ip)
                    + trusted_cidr.count(ip))))
        if current_cidr.count(ip) == 0 and \
           proposed_cidr.count(ip) == 0 and \
           staging_cidr.count(ip) == 0 and \
           trusted_cidr.count(ip) == 0:
            obsolete_cidr_.append(ip)
    logger.info('Obsolete cidr number: ' + str(len(obsolete_cidr_)))
    for ip in obsolete_cidr_:
        logger.info(ip)
    return obsolete_cidr_


def get_new_cidr():
    logger.info('Checking new cidr...')
    new_cidr_ = list()
    for ip in proposed_cidr:
        if current_cidr.count(ip) == 0:
            new_cidr_.append(ip)
    logger.info('New cidr number: ' + str(len(new_cidr_)))
    return new_cidr_


def add_missed_cidr():
    logger.info('\n------------Add Missed Cidr------------')
    if len(missed_cidr) == 0:
        logger.info('No missed cidr were found!')
        return False
    for cidr in missed_cidr:
        add_ingress(find_empty_slots(siteshield_sg_groups), cidr)
    return True

def add_new_cidr():
    logger.info('\n------------Add New Cidr------------')
    if len(new_cidr) == 0:
        logger.info('No new cidr were found!')
        return False
    for cidr in new_cidr:
        add_ingress(find_empty_slots(siteshield_sg_groups), cidr)
    return True


def remove_obsolete_cidr():
    logger.info('\n------------Remove Obsolete Cidr------------')
    if len(obsolete_cidr) == 0:
        logger.info('No obsoleted cidr were found!')
        return False
    for cidr in obsolete_cidr:
        remove_ingress(find_ingress_cidr(siteshield_sg_groups, cidr), cidr)
    return True


def get_cidr_info():
    logger.info('\n------------Results------------')
    logger.info('Current cidr number: ' + str(len(current_cidr)))
    logger.info('Proposed cidr number: ' + str(len(proposed_cidr)))
    logger.info('New cidr number: ' + str(len(new_cidr)))
    logger.info('Staging cidr number: ' + str(len(staging_cidr)))
    logger.info('Trusted cidr number: ' + str(len(trusted_cidr)))
    logger.info('Configed cidr number: ' + str(len(configed_cidr)))
    logger.info('Missed cidr number: ' + str(len(missed_cidr)))
    logger.info('Obsolete cidr number: ' + str(len(obsolete_cidr)))
    logger.info('Total empty slots: ' + str(total_empty_slots))


def health_check():
    global current_cidr
    global proposed_cidr
    global new_cidr
    global staging_cidr
    global configed_cidr
    global missed_cidr
    global obsolete_cidr
    global total_empty_slots
    logger.info('\n------------Diagnose------------')
    logger.info('Checking current cidr...')
    current_cidr = get_type_cidr(siteshield_map_ids, 'currentCidrs')
    logger.debug(str(current_cidr))

    logger.info('Checking proposed cidr...')
    proposed_cidr = get_type_cidr(siteshield_map_ids, 'proposedCidrs')
    logger.debug(str(proposed_cidr))

    logger.info('Checking staging cidr...')
    logger.debug(str(staging_cidr))
    staging_cidr = get_staging_cidr('staging_ip')

    logger.info('Checking configed cidr...')
    configed_cidr = get_configed_cidr(siteshield_sg_groups)
    logger.debug(str(configed_cidr))

    logger.info('Checking missed cidr...')
    missed_cidr = check_missed_cidr()
    logger.debug(str(missed_cidr))

    logger.info('Checking obsolete cidr...')
    obsolete_cidr = check_obsolete_cidr()
    logger.debug(str(obsolete_cidr))
    new_cidr = get_new_cidr()

    logger.info('Checking total empty slots...')
    total_empty_slots = get_total_empty_slots(siteshield_sg_groups)
    logger.debug(str(total_empty_slots))


def sssg_advisor():
    logger.info('\n------------Recommedations------------')
    recomm_list = list()
    if len(missed_cidr) > 0:
        recomm_list.append('- There are some site shield cidr are missed in the security groups. The details can be'
                           ' found in Diagnose, please add them in.')
    if len(obsolete_cidr) > 0:
        recomm_list.append('- There more some obsolete site shield cidr are still in the security groups. The details'
                           ' can be found in Diagnose, please remove them.')
    if len(proposed_cidr) > 0:
        recomm_list.append('- Site shield has new updates, please change the security groups accordingly.')
    if total_empty_slots < 5:
        recomm_list.append('- Security groups are reaching the rule limits, only less than 5 are left. Please clean up'
                           ' the obsolete cidr or add a new security group')
    if len(missed_cidr) - total_empty_slots > 0:
        recomm_list.append('- Security groups do not have enough spaces for the missed site shield cidr')
    if len(new_cidr) - total_empty_slots > 0:
        recomm_list.append('- Security groups do not have enough spaces for the new site shield cidr')
    if len(recomm_list) == 0:
        recomm_list.append('Congratulations! No issues were found.')
    for recomm in recomm_list:
        logger.info(recomm)


def sssg_main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--advisor', help='make recommedations based on current settings',
                        action='store_true')
    parser.add_argument('-d', '--debug', help='enable debug logging mode',
                        action='store_true')
    parser.add_argument('-i', '--mapinfo', help='get site shield map name and id',
                        action='store_true')
    parser.add_argument('-k', '--acknowledge', help='acknowledge site shield updates. Warning: ensure you update'
                                                    ' security groups before acknowledge', action='store_true')
    parser.add_argument('-m', '--missed', help='add missed site shield cidr to security groups',
                        action='store_true')
    parser.add_argument('-n', '--new', help='add new site shield cidr to security groups',
                        action='store_true')
    parser.add_argument('-o', '--obsolete', help='remove obsolete site shield cidr from security groups',
                        action='store_true')
    parser.add_argument('-s', '--search', metavar='cidr', help='find security group that contains this cidr'
                                                               ' (e.g 23.50.48.0/20)')

    args = parser.parse_args()
    if args.advisor:
        if args.debug:
            logger.setLevel(logging.DEBUG)
        health_check()
        get_cidr_info()
        sssg_advisor()
    if args.mapinfo:
        get_map_info()
    if args.acknowledge:
        if args.debug:
            logger.setLevel(logging.DEBUG)
        health_check()
        ack_proposed_cidr(siteshield_map_ids)
    if args.missed:
        if args.debug:
            logger.setLevel(logging.DEBUG)
        health_check()
        add_missed_cidr()
    if args.obsolete:
        if args.debug:
            logger.setLevel(logging.DEBUG)
        health_check()
        remove_obsolete_cidr()
    if args.new:
        if args.debug:
            logger.setLevel(logging.DEBUG)
        health_check()
        add_new_cidr()
    if args.search:
        find_ingress_cidr(siteshield_sg_groups, args.search)

if __name__ == '__main__':
    sssg_main()




