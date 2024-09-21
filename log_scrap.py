# -*- coding: UTF-8 -*-
# @CreateTime     :   2021/9/8 11:15
# @Author   :   nyan
# @TestVer
#Update
import time
import os,datetime
import get_district as val
import json
import re
from FTP2 import MyFTP
import sys
from new_version import LogInspect as value
import redis
from log_tools import logger
logger=logger()


reload(sys)
sys.setdefaultencoding('utf-8')

month_dict = {
    'Jan': '01',
    'Feb':'02',
    'Mar':'03',
    'Apr':'04',
    'May':'05',
    'Jun':'06',
    'Jul':'07',
    'Aug':'08',
    'Sep':'09',
    'Oct':'10',
    'Nov':'11',
    'Dec':'12'
}

class LogIncScaner(object):

    def __init__(self, path):
        self.target_dirs = self.search_target_dirs(path)
        self.seek = self.get_seek(self.target_dirs)  # 获取游标，如果有游标文件则获取到最新游标，没有则创建
        self.TIMES_SET=val.TIMES_SET
        self.UPLOAD_MSG_RANGE=val.UPLOAD_MSG_RANGE

    # 扫描目录下的ip文件夹

    def search_target_dirs(self, path):

        for root, dirs, files in os.walk(path):

            dirs.remove('127.0.0.1')
            return dirs

    # 扫描文件变动，并且获取增量日志
    def scan(self,log_file):



        for target_ip in self.target_dirs:

            content = []
            os.chdir(target_ip)
            # 游标随ip切换
            try:
                seek = self.seek[target_ip]
            except Exception as e :
                self.seek[target_ip]={"time": time.time(), "position": 0}
                seek = self.seek[target_ip]

            # #日志文件随ip切换

            if os.path.exists(log_file):

                # 修改时间是否变化
                file_mtime = os.path.getmtime(log_file)
                file_size = os.path.getsize(log_file)
                if (file_mtime <= seek['time'] and seek['position'] != 0) or file_size <= seek['position']:
                    os.chdir('../')
                    continue
                # 如i果变化 读取增量部分
                #print('nochange')
                with open(log_file, 'r+') as logfd:
                    logfd.seek(seek['position'], os.SEEK_SET)

                    # 读取增量行数
                    lines = logfd.readlines()
                    if lines:
                        for line in lines:
                            line=line.decode('gbk',errors='ignore').encode('utf-8')
                            line= line.replace('\n', '')
                            if line:
                                content.append(line)

                    # 更新游标
                    self.seek[target_ip] = {'time': time.time(), 'position': logfd.tell()}
                    seek = json.dumps(self.seek)

                    # 保存游标
                    os.chdir('../')
                    with open('cursor_log.txt', 'w') as cursor_log:
                        cursor_log.write(seek)

                    self.log_sending(content, target_ip)

            else:
                self.seek[target_ip]={'time':time.time(),'position':0}
                seek=json.dumps(self.seek)
                os.chdir('../')
                with open('cursor_log.txt','w') as cursor_log:
                    cursor_log.write(seek)
        return 0

    # 日志转txt
    def log_sending(self, content, target_ip):

        for log in content:

            # 日志格式处理
            loged = self.reCompile(log)
            if len(loged) < 3:
                logger.info(log)
                logger.info(loged[0] + ' from ' + target_ip + ',wrong format')
                continue

            # 分数获取、发送
            loged_detail = json.loads(loged[2])
            src_ip = loged_detail['source']['ip']
           
                continue

            # 产生文件名字
            file_name = self.output_txt_name(target_ip)

            if loged_detail['level'] >= 40:
                IP_inspector = value(loged_detail, src_ip, target_ip, loged)

                if loged_detail['level'] and 35 < loged_detail['level'] < 45:
                    logger.info(
                        '====got one level 40 record from' + target_ip + ',record time:' + loged[0] + ',src:' + src_ip)
                    IP_info = IP_inspector.analysis()
                    score = IP_info['history_score']
                    logger.info('====' + src_ip + ':' + str(score) + ' from ' + target_ip)
                    sent_status = int(IP_info['attack_send_status'])
                    Mtimes = IP_info['attack_Mlevel']

                    if self.TIMES_SET != 0 and Mtimes >= self.TIMES_SET and not sent_status:
                        logger.info(src_ip + 'sending..')
                        self.write_in_format_n_send2_ftp(loged_detail, file_name, log, loged)
                        IP_inspector.change_sent_status(src_ip)
                    elif not self.TIMES_SET and score >= 100 and not sent_status:
                        logger.info(src_ip + 'sending..')
                        self.write_in_format_n_send2_ftp(loged_detail, file_name, log, loged)
                        IP_inspector.change_sent_status(src_ip)
                # 等级50的日志直接发送
                elif loged_detail['level'] and loged_detail['level'] > 45:
                    logger.info('====got one serious log! sending')
                    self.write_in_format_n_send2_ftp(loged_detail, file_name, log, loged)
                    IP_inspector.change_sent_status(src_ip)

        return
    @staticmethod
    def time_now():
        return datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")

    @staticmethod
    def time_processed(str_1):

        str_temp = str_1.split(' ')
        for i in str_temp:
            if i == '':
                str_temp.remove(i)
        if len(str_temp[1]) < 2:
            str_temp[1] = '0' + str_temp[1]
        year = str(datetime.datetime.now().year)
        month = month_dict[str_temp[0]]
        day = str_temp[1]
        exact_time = str_temp[2]
        short_date = year + '-' + month + '-' + day
        long_date = year + '-' + month + '-' + day + ' ' + exact_time
        long_date = long_date.replace(':', '-')
        return [short_date, long_date]

    def get_seek(self, target_ips):

        # 如果没有游标记录文件，则创建
        if not os.path.exists('cursor_log.txt'):
            logger.info('新建游标文件')
            open('cursor_log.txt', 'w')
        # 如果有就获取
        with open('cursor_log.txt', 'r+') as cursor_log:
            logger.info('获取游标、游标文件内容初始化')

            try:
                line = cursor_log.readline()
                if line:
                    latest_cursor = json.loads(line)
                    return latest_cursor
                # 如果里面并没有内容，就创建一个新的游标点
                else:
                    seek = {}
                    for i in target_ips:
                        key = i
                        value = {"time": time.time(), "position": 0}
                        seek[key] = value
                    seek['days']=datetime.datetime.now().strftime('%Y-%m-%d')
                    seek_w=json.dumps(seek)
                    cursor_log.write(seek_w)
                    return seek

            except Exception as e:
                logger.error(e)

    # 清空游标记录文件
    def reset_seek_n_cursor(self):
        try:
            if os.path.exists('cursor_log.txt'):
                os.remove('cursor_log.txt')
                self.seek = self.get_seek(self.target_dirs)
                logger.info('游标已重置')
            if os.path.exists('sent_loged.txt'):
                os.remove('sent_loged.txt')
                logger.info('发送记录已重置')

            pool = redis.ConnectionPool(host='localhost', port=6379)
            red = redis.Redis(connection_pool=pool)
            red.flushall()
            logger.info('redis已重置')
        except Exception as e:
            logger.error(e)



    # 产生文件名字
    def output_txt_name(self, target_ip):
        return target_ip+'--'+datetime.datetime.now().strftime('%Y-%m-%d %H-%M-%S')+ '_log.txt'

    # 处理每条日志
    @staticmethod
    def reCompile(content):
        a = []
        retime = re.compile(r'(\w+\s+\w+\s+[0-9]+:[0-9]+:[0-9]+)')
        reipAdress = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
        # reipAdress = re.compile(r'(localhost)')
        redetail = re.compile(r'{.*}')
        redetail_filter = re.compile(r'"message":"(.*)","securityid"')
        try:
            msgtime = re.findall(retime, content)[0]
            a.append(msgtime)
            ipAddress = re.findall(reipAdress, content)

            if ipAddress and (ipAddress[0] == '21.136.96.26' or ipAddress[0] == '21.136.96.27'):
                return ['', '']
            else:
                a.append(' ')
            rubbish = re.findall(redetail_filter, content)[0]
            detail = re.findall(redetail, content)[0]
            detail = detail.replace(rubbish, "")
            a.append(detail)
        except Exception as e:
            logger.error(e)

        return a



    def sub_bank_name(self,des_ip):
        pass
    # 转化格式,发送

    def write_in_format_n_send2_ftp(self,loged_detail, file_name, log_full,loged):
        if not os.path.exists('sent_loged.txt'):
            open('sent_loged.txt', 'w')
        with open('sent_loged.txt', 'a') as sent_loged:
            sent_loged.write(log_full + '\r\n')
        current_time=self.time_processed(loged[0])[0]
        time_simplify=self.time_processed(loged[0])[1]
        detail = loged_detail
        key = '日志事件告警监控' + time_simplify
        product_level = detail['level']
        systemid = detail['id']
        level = ''
        level_class = ''
        symbol = ' (异常)'
        subject = detail['subject'].decode('utf-8')
        msg = detail['message'].decode('utf-8')
        source_ip = json.dumps(detail['source']['ip'])
        source_port = json.dumps(detail['source']['port'])
        destination_ip = json.dumps(detail['destination']['ip'])
        destination_port = json.dumps(detail['destination']['port'])
        bank_name=sub_bank_name(loged_detail['destination']['ip'])

        if product_level >= 40:
            if detail['level'] >= 50:
                level_class = '一级告警'
            elif 50 > detail['level'] >= 10:
                level_class = '二级告警'

            raw_email = ''
            if os.path.exists('sent_to.txt'):
                sent_to_file = open('sent_to.txt', 'r')
                raw_email = sent_to_file.readline()
            with open(file_name, 'wb', ) as targetFile:
                data = 'TextEvent[#' + current_time + '#]\r\n\
    key[#' + key + '#]\r\ndt[#' + current_time + '#]\r\nsource[#日志事件告警监控#]\r\n\
    target[#告警事件监控#]\r\nclassic[#对日志生成#]\r\n\
    level[#' + str(product_level) + '#]\r\n\
    subject[#【' + level_class + '】' + time_simplify + '  ' + subject + symbol + ' #]\r\n\
    content[#来源:' + source_ip + ':' + source_port + '   目标：' + destination_ip + ':' + destination_port + '#]\r\n\
    reserve1[##]\r\n\
    reserve2[##]\r\n\
    reserve3[##]\r\n\
    extradata[##]\r\nsendnotes[#y#]\r\n\
    hassent[#n#]\r\nsendreceiver[#' + raw_email + '#]\r\n\
    sendcopy[##]\r\n\
    sendsms[#y#]\r\nsmstext[#【' + level_class + '】' + time_simplify + '  ' + subject + symbol + ' #]\r\n\
    mobiles[#''#]\r\nmakevoice[##]\
    '

                data = data.decode('utf-8', errors='ignore').encode('GBK', errors='ignore')
                targetFile.write(data)
            try:
                my_ftp = MyFTP('..', '','')
                my_ftp.upload_file(file_name, file_name)  # 本地文件名   传到ftp上的目录及名字
                my_ftp.close()
            except Exception as e :
                logger.error(e)
                logger.error(log_full)
            os.remove(file_name)

if __name__ == "__main__":

  
    scaner = LogIncScaner(path='')
    target_ips=scaner.search_target_dirs(path='')
    print ('已启动')
    while True:

        with open('cursor_log.txt','r') as cursor_log:
            line = cursor_log.readline()
            cursor = json.loads(line)
        if cursor['days']!=datetime.datetime.now().strftime('%Y-%m-%d'):
            scaner.reset_seek_n_cursor()
            logger.info('日期已变更！')
            log_file=datetime.datetime.now().strftime('%Y-%m-%d')+'.log'
           
        else:
            log_file = cursor['days'] + '.log'
        logger.info('目前扫描文件名字为:'+log_file)
        scaner.scan(log_file)
        time.sleep(2)

          


