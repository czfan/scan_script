#-*- coding:utf-8 -*-
import urllib2
import ssl
import json
import sys
import threading
from time import ctime,sleep
from threading import Lock
__author="tahm"

username='wvs@com.cn'
#�˺�����
pw='a6cbbed511ececcb9ca96c3024e7efcf513ec194259831fdd2f3a742b57c4705'
#sha256���ܺ������
#HOST='192.168.137.129:13443'
HOST='localhost:4343'
#��Ҫ��ӵ�url�б����awvs.txt�ļ������ڸýű������нű���
ssl._create_default_https_context = ssl._create_unverified_context
DESCRIPTION = "222"
##############################################################################################
#����ȫ��Ŀ���б�

#targets_global = {'completed':completed,'failed':failed,'never':never}
targets_global = {}
#scans_global={'failed':failed_s,'never':never_s,'aborted':aborted_s,'aborting':aborting_s,'completed':completed_s,'failed':failed_s,'processing':processing_s,'queued':queued_s,'scheduled':scheduled_s,'starting':starting_s,'pausing':pausing_s,'resuming':resuming_s,'paused':paused_s,}
##############################################################################################
scans_global={}
##############################################################################################

##############################################################################################
lock = threading.Lock()
printer_lock = threading.Lock()
MAIN_EVENT = threading.Event()
class Traffic:
	def __init__(self, name, count, lock):
		self.name = name
		self.count = count
		self._count = count
		self.lock = lock
		self._callback = None
		self.args = None

	def acquire(self):
		self._count = self._count - 1

	def release(self):
		lock.acquire()
		self._count = self._count + 1
		if self._count == self.count:
			printstr("release done")
			self.notify()
		lock.release()

	def reset(self, count):
		self.count = count
		self._count = count
		if not count > 0:
			printstr("count <= 0: %d" % count)
			self.notify()

	def notify(self):
		printstr(self._count)
		printstr(self.count)
		printstr(self._callback == None)
		if self._callback == None:
			printstr("event.set")
			MAIN_EVENT.set()
		else:
			printstr("callback.call")
			self._callback(self.args)
			self._callback = None
			self.args = None

	def callback(self, func, args):
		self._callback = func
		self.args = args

#�����߳�֪ͨ
TRAFFIC = Traffic("���߳̿���", 100, lock)
##############################################################################################
def printstr(str):
	printer_lock.acquire()
	print str
	printer_lock.release()
##############################################################################################
def login():
	url_login="https://%s/api/v1/me/login" % HOST
	printstr(url_login)
	send_headers_login={
		'Host': '%s' % HOST,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
		'Accept-Encoding': 'gzip, deflate, br',
		'Content-Type': 'application/json;charset=utf-8',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36'
	}
	data_login='{"email":"'+username+'","password":"'+pw+'","remember_me":false,"logout_previous":true}'
	req_login = urllib2.Request(url_login,headers=send_headers_login)
	response_login = urllib2.urlopen(req_login,data_login)
	xauth = response_login.headers['X-Auth']
	COOOOOOOOkie = response_login.headers['Set-Cookie']
	global send_headers
	send_headers={
		'Host': '%s' % HOST,
		'Accept': 'application/json, text/plain, */*',
		'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
		'Accept-Encoding': 'gzip, deflate, br',
		'Content-Type': 'application/json;charset=utf-8',
		'X-Auth':xauth,
		'Cookie':COOOOOOOOkie,
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36'
	}
	printstr("��ǰ��֤��Ϣ����\r\n cookie : %r  \r\n X-Auth : %r  "%(COOOOOOOOkie,xauth))

#define engine
def engine():
	url_workers="https://%s/api/v1/workers" % HOST
	req_workers=urllib2.Request(url_workers,headers=send_headers)
	response_workers = urllib2.urlopen(req_workers)
	workers = json.loads(response_workers.read())['workers']
	global worker_id
	worker_id = workers[0]['worker_id']
	printstr("%d %s %s"%(len(workers),workers[0]['description'],worker_id))

##############################################################################################
#���߳�ʵ�֣����з�������:
#arg: url or target
#options: {'target':True, 'scan':True} ��һ������ȷ����Target����Url.�����Target�ڶ�������ȷ���Ƿ���Ҫ����ɨ��

def scan(arg,options):
	target_id = arg
	if options['target']:
		target_id = add_target(target_id)
	if options['scan']:
		scan_target(target_id)
	TRAFFIC.release()

def add_target(url):
	url_target="https://%s/api/v1/targets" % HOST
	try:
		target_url = url.strip()
		data='{"description":"%s","address":"%s","criticality":"10"}' % (DESCRIPTION, target_url)
		#data = urllib.urlencode(data)����ʹ��json��ʽ���Բ������
		req = urllib2.Request(url_target,headers=send_headers)
		response = urllib2.urlopen(req,data)
		jo=json.loads(response.read())
		target_id=jo['target_id']#��ȡ��Ӻ������ID
		#ΪĿ�����ɨ������
		target_engine="https://%s/api/v1/targets/%s/configuration/workers" % (HOST, target_id)
		data_engine='{"worker_id_list":["%s"]}' % worker_id
		req_engine = urllib2.Request(target_engine,headers=send_headers)
		response_engine = urllib2.urlopen(req_engine,data_engine)
		#���ϴ���ʵ���������
	except Exception,e:
		printstr(e)
		sys.exit()
	printstr("���Ŀ��ɹ�[%s]:[%s]" % (target_id.decode('ascii').encode('utf-8'), target_url))
	return target_id

def scan_target(target_id):
	try:
		url_scan="https://%s/api/v1/scans" % HOST
		data_scan='{"target_id":'+'\"'+target_id+'\"'+',"profile_id":"11111111-1111-1111-1111-111111111111","schedule":{"disable":false,"start_date":null,"time_sensitive":false},"ui_session_id":"66666666666666666666666666666666"}'
		req_scan=urllib2.Request(url_scan,headers=send_headers)
		response_scan=urllib2.urlopen(req_scan,data_scan)
		#���ϴ���ʵ������ɨ��
	except Exception,e:
		printstr(e)
		sys.exit()
	printstr("���ɨ��ɹ�[%s]" % target_id.decode('ascii').encode('utf-8'))

#del_targets()
#arg: target or scan
#options: {'target':True} ��һ������ȷ����Target����scan.
def delete(arg,options):
	try:
		if options['target']:
			url = "https://%s/api/v1/targets/" % HOST + str(arg["target_id"])
			description = arg["description"]
		else:
			url = "https://%s/api/v1/scans/" % HOST + str(arg["scan_id"])
			description = arg["target"]["description"]
		if options['ignore_description'] or description == DESCRIPTION:
			req_del = urllib2.Request(url,headers=send_headers)
			req_del.get_method =lambda: 'DELETE'
			response_del = urllib2.urlopen(req_del)
			printstr('ɾ���ɹ�')
	except Exception,e:
		printstr(e)
		sys.exit()
	TRAFFIC.release()

def del_scans(options):
	try:
		ignore_description = options['ignore_description']
		if options['ignore_status']:
			scans = scans_global['all']
		else:
			scans = scans_global['completed']
		TRAFFIC.reset(len(scans))
		_t = []
		for scan in scans:
			t = threading.Thread(target=delete,args=(scan,{'target':False, 'ignore_description': ignore_description},))
			TRAFFIC.acquire()
			_t.append(t)
		for t in _t:
			t.start()
	except Exception,e:
		printstr(e)
#del_scan()			#ͨ�������ж��Ƿ�ʹ��ɨ�������ɨ������ӵ�ʱ������description=��222��

def del_targets(options):
	try:
		ignore_description = options['ignore_description']
		if options['ignore_status']:
			targets = targets_global['all']
		else:
			targets = targets_global['completed']
		TRAFFIC.reset(len(targets))
		_t = []
		for target in targets:
			t=threading.Thread(target=delete,args=(target,{'target':True, 'ignore_description': ignore_description},))
			TRAFFIC.acquire()
			_t.append(t)
		for t in _t:
			t.start()
	except Exception,e:
		printstr(e)

def del_truncate(options):
	TRAFFIC.callback(del_targets, options)
	del_scans(options)


#del_targets()

#���ϴ���ʵ�ֵ�¼����ȡcookie����У��ֵ
def add_exec_scan():
	try:
		urllist=open('awvs.txt','r')#����Ҫ��ӵ�url�б�
		formaturl=urllist.readlines()
		TRAFFIC.reset(len(formaturl))
		_t = []
		for i in formaturl:
			t=threading.Thread(target=scan,args=(i.strip(),{'target':True, 'scan':False},))
			TRAFFIC.acquire()
			_t.append(t)
		for t in _t:
			t.start()
		urllist.close()
	except Exception,e:
		printstr(e)

#ʣ��Ŀ�����ɨ��
def add_scan():
	try:
		TRAFFIC.reset(len(targets_global['never']))
		_t = []
		for target in targets_global['never']:
			t=threading.Thread(target=scan,args=(target['target_id'],{'target':False, 'scan':True},))
			TRAFFIC.acquire()
			_t.append(t)
		for t in _t:
			t.start()
	except Exception,e:
		printstr(e)
#scan--status
#Aborted
#Aborting
#Completed
#Failed
#Processing
#Queued
#Scheduled
#Starting
#Pausing
#Resuming
#Paused
def count():
	url_count="https://%s/api/v1/notifications/count" % HOST
	req_count=urllib2.Request(url_count,headers=send_headers)
	response_count=urllib2.urlopen(req_count)
	printstr("��ǰ����%r��֪ͨ��" % json.loads(response_count.read())['count'])
	target_count()
	scan_count()

def target_count():
	printstr("-" * 50)
	all=[]
	completed=[]
	failed=[]
	never=[]
	deleted=[]
	url_="https://%s/api/v1/targets?c=" % HOST
	url="https://%s/api/v1/targets" % HOST
	_cursor=0
	while True:
		req = urllib2.Request(url,headers=send_headers)
		response = urllib2.urlopen(req)
		jo=json.loads(response.read())
		targets = jo['targets']
		for target in targets:
			all.append(target)
			if target['last_scan_session_status'] == 'completed':
				completed.append(target)
			elif target['last_scan_session_status'] == 'failed':
				failed.append(target)
			elif target['last_scan_session_status'] == 'deleted':
				deleted.append(target)
			elif target['last_scan_session_status'] == None:
				never.append(target)
		url = url_
		if len(targets)==100:
			_cursor+=100
			url+=str(_cursor)
		else:
			_cursor+=len(targets)
			targets_global['all']=all
			targets_global['completed']=completed
			targets_global['failed']=failed
			targets_global['never']=never
			targets_global['deleted']=deleted
			break
	printstr("�� %r��Ŀ��, ����� %r��, ʧ�� %r��, δɨ�� %r��, ��ɾ��ɨ�� %r��." % (_cursor, len(completed), len(failed), len(never), len(deleted)))

def scan_count():
	printstr("-" * 50)
	all=[]
	failed=[]
	never=[]
	aborted=[]
	aborting=[]
	completed=[]
	processing=[]
	queued=[]
	scheduled=[]
	starting=[]
	pausing=[]
	resuming=[]
	paused=[]
	url_="https://%s/api/v1/scans?c=" % HOST
	url="https://%s/api/v1/scans" % HOST
	_cursor=0
	while True:
		req = urllib2.Request(url,headers=send_headers)
		response = urllib2.urlopen(req)
		jo=json.loads(response.read())
		scans=jo['scans']
		for scan in scans:
			all.append(scan)
			if scan['current_session']['status'] == 'completed':
				completed.append(scan)
			if scan['current_session']['status'] == 'failed':
				failed.append(scan)
			if scan['current_session']['status'] == 'aborted':
				aborted.append(scan)
			if scan['current_session']['status'] == 'aborting':
				aborting.append(scan)
			if scan['current_session']['status'] == 'processing':
				processing.append(scan)
			if scan['current_session']['status'] == 'queued':
				queued.append(scan)
			if scan['current_session']['status'] == 'scheduled':
				scheduled.append(scan)
			if scan['current_session']['status'] == 'starting':
				starting.append(scan)
			if scan['current_session']['status'] == 'pausing':
				pausing.append(scan)
			if scan['current_session']['status'] == 'resuming':
				resuming.append(scan)
			if scan['current_session']['status'] == 'paused':
				paused.append(scan)
			elif scan['current_session']['status'] == None:
				never.append(scan)
		url = url_
		if len(scans)==100:
			_cursor+=100
			url+=str(_cursor)
		else:
			_cursor+=len(scans)
			scans_global['all']=all
			scans_global['aborted']=aborted
			scans_global['aborting']=aborting
			scans_global['completed']=completed
			scans_global['failed']=failed
			scans_global['processing']=processing
			scans_global['queued']=queued
			scans_global['scheduled']=scheduled
			scans_global['starting']=starting
			scans_global['pausing']=pausing
			scans_global['resuming']=resuming
			scans_global['paused']=paused
			break
	printstr("�� %r ��ɨ��, ����� %r ��,ʧ�� %r ��,�Ӳ� %r ��,����ֹ %r ��,������ֹ %r ��,���ڴ��� %r ��,�Ŷӵ� %r ��,�ƻ��� %r ��,�������� %r ��,������ͣ %r ��,���ڻָ� %r ��,��ͣ�� %r ��." % (_cursor,len(completed),len(failed),len(never),len(aborted),len(aborting),len(processing),len(queued),len(scheduled),len(starting),len(pausing),len(resuming),len(paused)))

#scan��target��notification��

def validateSession():
	url="https://%s/api/v1/info" % HOST
	try:
		req_validate=urllib2.Request(url,headers=send_headers)
		response_scan=urllib2.urlopen(req_validate)
	#���ϴ���ʵ����������ɨ��
	except Exception,e:
		printstr('�ỰʧЧ���������µ�½!')
		return False
	return True

def main():
	printstr("*" * 20)
	printstr("0��������Ŀ�����ɨ������ִ��������0.\r\n1��ʹ��awvs.txt���ɨ������ִ��������1.\r\n2��ɾ�����нű���ӵ�ɨ��Ŀ��������2.\r\n3��ɾ�����нű���ӵ�ɨ������������3.\r\n4���鿴ɨ�����������4.\r\n5�����ȫ��������5.\r\n6������Ĭ������������6.\r\n")
	choice = raw_input(">")
	if not validateSession(): login()
	try:
		if choice =="0":
			add_scan()
			MAIN_EVENT.wait()
		elif choice =="1":
			add_exec_scan()
			MAIN_EVENT.wait()
		elif choice =="2":
			del_targets({"ignore_description": False, "ignore_status": False})
			MAIN_EVENT.wait()
		elif choice =="3":
			del_scans({"ignore_description": False, "ignore_status": False})
			MAIN_EVENT.wait()
		elif choice =="4":
			count()
		elif choice =="5":
			choice = raw_input("��0����ձ�ǩȫ��. ��1�����ȫ��. >")
			del_truncate({"ignore_description": int(choice), "ignore_status": True})
			MAIN_EVENT.wait()
		elif choice =="6":
			global DESCRIPTION
			DESCRIPTION = raw_input("����������%s��>" % DESCRIPTION)
		else:
			sys.exit()
		if not choice =="4":
			count()
	except Exception,e:
		printstr(e)

if __name__== "__main__":
	login()
	engine()
	count()
	while True:
		main()