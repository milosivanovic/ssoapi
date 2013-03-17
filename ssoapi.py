#!/usr/bin/python

"""

Copyright (C) 2011-2013 Milos Ivanovic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import sys
import urllib, urllib2
import cookielib
import lxml.html, lxml.etree
import random
import time

class XPath(object):

	def parser(self, expression, input, list = False):
		if type(input) == str:
			result = lxml.html.fromstring(input)
		elif type(input) == lxml.etree._ElementTree:
			result = input
		else:
			result = lxml.html.parse(input)
		
		if expression:
			findings = result.xpath(expression)
		else:
			return result
		
		if findings:
			if list:
				return findings
			else:
				return findings[0]
		else:
			return None
		

class SSOAPI(object):
	
	def __init__(self, username, password, debug = False):
		self.xpath = XPath().parser
		self.debug = debug
		self.username = username
		self.password = password
		self.urls = [
			'https://www.student.auckland.ac.nz',
			'https://iam.auckland.ac.nz/Authn/UserPassword',
			'/ps%s/ps/EMPLOYEE/HRMS/c/SA_LEARNER_SERVICES.%s.GBL'
		]
		self.default_component = 'SSS_STUDENT_CENTER'
		self.last_component = None
		self._build_session()
	
	def _build_session(self):
		self.session = cookielib.CookieJar()
		self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.session))
		self.opener.addheaders = [('User-Agent', 'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:19.0) Gecko/20100101 Firefox/19.0')]
		self.login_time = None
		self.current_user = None
	
	def _fetch(self, url, params = None):
		retry = 0
		while True:
			try:
				obj = self.opener.open(url, params)
				if self.login_time and (obj.geturl().replace(':443', '') == self.urls[1] or retry > 0):
					self.reset()
					return self._fetch(url, params)
				else:
					return obj
			except urllib2.URLError, e:
				if getattr(e, 'code', False):
					self.reset()
					raise
				time.sleep(1)
				retry += 1
		self._abort(e)
	
	def _log(self, message, severity = 0):
		if self.debug:
			print message
		if severity >= 1:
			return False
	
	def _abort(self, e):
		self._log("\n[ !! ] Unrecoverable error (details: %s); aborting\n" % (e or 'unknown'), 2)
		#sys.exit(getattr(e, 'code', -1))
	
	def login(self):
		if not self.login_time:
			self.login_time = 0
			if self._idp_login():
				self.login_time = time.time()
				return True
		else:
			self._log('Already logged in.')
			return False
	
	def reset(self):
		if self.login_time:
			self._build_session()
			self.login()
			return True
		self._log('Not logged in yet.')
		return False
	
	def logout(self):
		if self.login_time:
			self._build_session()
			return True
		self._log('Not logged in yet.')
		return False
	
	def _idp_login(self):
		self._log("* Shibboleth IdP")
		self._log("** Loading login page...")
		self._fetch('%s/' % self.urls[0])
		
		# login onto the identity provider
		self._log("** Sending encapsulated credentials...")
		ssosubmit = self._fetch(self.urls[1], urllib.urlencode(
			{
				'submitted':	1,
				'j_username':	self.username,
				'j_password':	self.password,
			}
		))
		if not ssosubmit:
			return self._log('Error sending credentials.', 1)
		elif ssosubmit.geturl().replace(':443', '') == self.urls[1]:
			return self._log('Invalid credentials.', 1)
		ssopagexp = self.xpath(None, ssosubmit, True)
		
		# send authentication response
		self._log("** Exchanging session data...")
		saml = self._fetch('%s/Shibboleth.sso/SAML2/POST' % self.urls[0], urllib.urlencode(
			{
				'RelayState':	self.xpath("//input[@name='RelayState']/@value", ssopagexp),
				'SAMLResponse':	self.xpath("//input[@name='SAMLResponse']/@value", ssopagexp)
			}
		))
		if not saml:
			return self._log('Error with SAML exchange.', 1)
		
		return self._sso_login()
	
	def _sso_login(self):
		# load SSO homepage
		self._log("\n* Oracle PeopleSoft")
		self._log("** Loading SSO homepage...")
		ssoframes = self._fetch('%s%s?cmd=login' % (self.urls[0], self.urls[2] % ('p', self.default_component)), urllib.urlencode(
			{
				'timezoneOffset':	-780,
				'userid':			'%s*sso' % self.username,
				'pwd':				'ssologin%d' % random.randint(1, 1000000000000)
			}
		))
		if not ssoframes:
			return self._log('Error loading SSO frame data.', 1)
		
		# load main HTML frame and grab SID and user's first name
		self._log("** Loading primary frame...")
		homepage = self._fetch(self.xpath("//frame[@name='TargetContent']/@src", ssoframes)).read()
		
		icsid = self.xpath("//input[@name='ICSID']/@value", homepage)
		if not icsid:
			return self._log('Error loading primary data frame.', 1)
		self._log("** Received session ID: %s" % icsid)
		
		self.current_user = self.xpath("//span[starts-with(@id, 'UOA_DERIVED_SSS_TITLE1')]/text()", homepage).split()[1]
		
		return True

	def call(self, component, action = None, params = {}):
		if self.login_time:
			component = self.default_component if not component else component
			recurse = True if self.last_component != component and action else False
			self.url = '%s%s' % (self.urls[0], self.urls[2] % ('c', component))
			self.params = {'ICAction': action} if action else {}
			
			if params:
				self.params.update(params)
			
			if recurse:
				self._log("Loading %s -> Default..." % component)
				self._submit(with_params = False)
			
			self._log("Loading %s -> %s..." % (component, self.params.get('ICAction', 'Default')))
			self._log("Params: %s\n" % dict((k, v) for (k, v) in self.params.iteritems() if k != 'ICAction'))
			
			self.last_component = component
			
			return self._parse(component, self._submit(post = True if params else False))
			
		self._log('Not logged in.')
		return False
	
	def _submit(self, post = False, with_params = True):
		params = self.params if with_params else {}
		
		if post:
			result = self._fetch(self.url, urllib.urlencode(params)).read()
		else:
			result = self._fetch("%s?%s" % (self.url, urllib.urlencode(params))).read()
		
		return result
	
	def _parse(self, component, html):
		return html
		# this method does nothing whatsoever (yet)

		
if __name__ == "__main__":
	print "Usage: place this module in the same directory as your python script and import it"
	
	'''
	
	QUICK START GUIDE WITH A FEW SIMPLE EXAMPLES
	------------------------------------------------------------------------------------------
	1.	Install any missing dependencies (probably lxml)
	
	2.	Either interactively load Python and import the module, which needs to be in the same
		directory as your current working directory:
		>>> import ssoapi
		>>> [further commands go here]
	
		OR
	
		Write a script; the commands are the same as with the interactive interpreter.
	
	3.	Create an instance of the SSOAPI class
		api = ssoapi.SSOAPI('user', 'pass')
		You may pass an optional argument to increase verbosity: SSOAPI('user', 'pass', True)
	
	4.	Login using the API
		api.login()
		The user's first name is stored in api.current_user to use if needed.
		You can also logout at any time by using api.logout() or if you want to reset
		your session (logout and login), use api.reset()
	
	5.	Select an API call; you will receive the HTML for the requested page
	
		SSO homepage
		api.call(None)
		
		List all graded semesters since induction
		api.call('SSR_SSENRL_GRADE')
	
		Current semester timetable
		api.call('SSR_SSENRL_LIST', 'DERIVED_SSS_SCT_SSR_PB_GO', {'SSR_DUMMY_RECV1$sels$0': '0'})

		Next semester timetable
		increase the value of 'SSR_DUMMY_RECV1$sels$0' from '0' to '1' - that means this here ^
		(0 means first choice on any ordered SSO list, 1 means second, and so on)
	
		Latest-enrolled semester grades
		api.call('SSR_SSENRL_GRADE', 'DERIVED_SSS_SCT_SSR_PB_GO', {'SSR_DUMMY_RECV1$sels$0': '0'})
	
		Second-latest-enrolled semester grades
		increase the value of 'SSR_DUMMY_RECV1$sels$0' from '0' to '1'
	
		-------------------------------------------------------------------------------------------
		If you want other features, find out what you need to request to get the page you want.
		Live HTTP Headers is the Firefox add-on that was used in the making of this API.
		-------------------------------------------------------------------------------------------
	
	HOW TO FIND YOUR OWN API CALLS TO USE WITH THIS MODULE
	-----------------------------------------------------------------------------------------------
	Note that depending on what you would like to achieve, steps 3 and 4 may be optional.
	
	1.	To be able to see the frame URL successfully you must choose to view only the main frame
		while exploring SSO. On Firefox this can be done by right-clicking and choosing:
		
	                              This Frame -> Show Only This Frame
	
	2.	Paying attention to the URL, you will see that there is a dynamic section, between the
		two dots near the right end:
		
	                /psc/ps/EMPLOYEE/HRMS/c/SA_LEARNER_SERVICES.SSS_STUDENT_CENTER.GBL
					
		'SSS_STUDENT_CENTER' is what is being referred to in this example, which is the first
		parameter for api.call() if you are interested in this page.
	
	3.	Now it is necessary to look for the value of the hidden ICAction form field.
		When hovering on the link you want the API to emulate a click on, you will notice
		the browser's status area display something like the below, with a capitalised section:
		
		javascript: hAction_win0(document.win0,'DERIVED_SSS_SCR_SSS_LINK_ANCHOR2',%200, ... );
		
		'DERIVED_SSS_SCR_SSS_LINK_ANCHOR2' is what is being referred to in this example, which
		is also coincidentally the second parameter for api.call().
	
	4.	When the link explained in the previous step is clicked on, it will submit an AJAX
		POST request to the server which you may or may not need to scrape (spy on) to match
		with this API. You may specify as little or as many additional parameters to api.call()
		as needed to generate the same result as your browser.
		
	A full API call of the above scenario is exposed below.
	
	api.call('SSS_STUDENT_CENTER', 'DERIVED_SSS_SCR_SSS_LINK_ANCHOR2', {
		'param1': 'value1',
		'param2': 'value2',
		'param3': 'value3'
	})
	
	This submits the link DERIVED_SSS_SCR_SSS_LINK_ANCHOR2 to page SSS_STUDENT_CENTER with
	parameters
	
				param1 => value1
				param2 => value2
				param3 => value3
				
	and returns the HTML content of whatever this might generate.
	
	It's now up to you to extend this API and parse the response.
	
	'''
