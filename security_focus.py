from html.parser import HTMLParser
import urllib.request
import string

class MyHTMLParser(HTMLParser):		#parses cve_id,products,attack from
	def __init__(self,strict=False):
		HTMLParser.__init__(self,strict)
		self.cve_id=''
		self.products=[]
		self.attack_from=''
		self.cve=False
		self.prod=False
		self.attk=False
		self.tr=False
		self.rmt=False
		self.lcl=False

	def handle_starttag(self,tag,attrs):
		if tag == 'tr':
			self.tr=True
			self.prod=False
			
	def handle_endtag(self,tag):
		if tag == 'tr':
			self.tr=False
			self.cve=False
			
	def handle_data(self,data):
		data=data.strip()
		if len(data) == 0:
			return
		if self.cve:
			self.cve_id=data[-9:]
		if self.rmt:
			if 'Yes' in data:
				self.attack_from='Remote '
				self.rmt=False
		if self.lcl:
			if 'Yes' in data:
				self.attack_from+='Local'
				self.lcl=False
		if self.prod:
			self.products.append(data)
			
		if self.tr:
			if data == 'CVE:':
				self.cve=True
			if data == 'Remote:':
				self.rmt = True
			if data == 'Local:':
				self.lcl = True
			if data == 'Vulnerable:':
				self.prod=True

	def get_cve_id(self):
		return self.cve_id

	def get_products(self):
		return self.products

	def get_attack_from(self):
		return self.attack_from
		
class Parse_discuss(HTMLParser):
	def __init__(self,strict=False):
		HTMLParser.__init__(self,strict)
		self.description=''
		self.desc=False
		self.span=False

	def handle_starttag(self,tag,attrs):
		if tag == 'div':
			for name,value in attrs:
				if name == 'id' and value == 'vulnerability':
					self.desc=True
		if tag == 'span':
			self.span=True

	def handle_endtag(self,tag):
		if tag == 'div':
			self.desc=False
		if tag == 'span':
			self.span=False
	def handle_data(self,data):
		if self.desc and not self.span:
			self.description+=(data.strip() + ' ')
	def get_description(self):
		return self.description

class Parse_impact(HTMLParser):
	def __init__(self,strict=False):
		HTMLParser.__init__(self,strict)
		self.impact=''
		self.impt=False
		self.span=False

	def handle_starttag(self,tag,attrs):
		if tag == 'div':
			for name,value in attrs:
				if name == 'id' and value == 'vulnerability':
					self.impt=True
		if tag == 'span':
			self.span=True

	def handle_endtag(self,tag):
		if tag == 'div':
			self.impt=False
		if tag == 'span':
			self.span=False
	def handle_data(self,data):
		if self.impt and not self.span:
			self.impact+=(data.strip() + ' ')
	def get_impact(self):
		return self.impact

class Parse_solution(HTMLParser):
	def __init__(self,strict=False):
		HTMLParser.__init__(self,strict)
		self.solution=''
		self.sol=False
		self.span=False

	def handle_starttag(self,tag,attrs):
		if tag == 'div':
			for name,value in attrs:
				if name == 'id' and value == 'vulnerability':
					self.sol=True
		if tag == 'span':
			self.span=True

	def handle_endtag(self,tag):
		if tag == 'div':
			self.sol=False
		if tag == 'span':
			self.span=False
	def handle_data(self,data):
		if self.sol and not self.span:
			if data == 'Solution:':
				return
			self.solution+=(data.strip() + ' ')
	def get_solution(self):
		return self.solution

class Parse_references(HTMLParser):
	def __init__(self,strict=False):
		HTMLParser.__init__(self,strict)
		self.references=[]
		self.ref=False
		self.span=False
		self.a=False

	def handle_starttag(self,tag,attrs):
		if tag == 'div':
			for name,value in attrs:
				if name == 'id' and value == 'vulnerability':
					self.ref=True
		if tag == 'span':
			self.span=True
		if tag == 'a':
			if self.ref:
				for name,value in attrs:
					if name =='href':
						self.references.append(value)

	def handle_endtag(self,tag):
		if tag == 'div':
			self.ref=False
		if tag == 'span':
			self.span=False
			
	def get_references(self):
		return self.references
		
def main():
	url='http://www.securityfocus.com/bid/59580/info'
	request = urllib.request.Request(url)
	request.add_header("User-Agent", "My Crawler")
	opener = urllib.request.build_opener()
	f = opener.open(request)
	#f = urllib.request.urlopen(url)
	st = f.read().decode('utf-8');
	parse = MyHTMLParser()
	parse.feed(st)
	url='http://www.securityfocus.com/bid/59580/discuss'
	request = urllib.request.Request(url)
	request.add_header("User-Agent", "My Crawler")
	opener = urllib.request.build_opener()
	f = opener.open(request)
	#f = urllib.request.urlopen(url)
	st = f.read().decode('utf-8');
	parse_desc = Parse_discuss()
	parse_desc.feed(st)
	url='http://www.securityfocus.com/bid/59580/exploit'
	request = urllib.request.Request(url)
	request.add_header("User-Agent", "My Crawler")
	opener = urllib.request.build_opener()
	f = opener.open(request)
	#f = urllib.request.urlopen(url)
	st = f.read().decode('utf-8');
	parse_impt = Parse_impact()
	parse_impt.feed(st)
	url='http://www.securityfocus.com/bid/59580/solution'
	request = urllib.request.Request(url)
	request.add_header("User-Agent", "My Crawler")
	opener = urllib.request.build_opener()
	f = opener.open(request)
	#f = urllib.request.urlopen(url)
	st = f.read().decode('utf-8');
	parse_sol = Parse_solution()
	parse_sol.feed(st)
	url='http://www.securityfocus.com/bid/59580/references'
	request = urllib.request.Request(url)
	request.add_header("User-Agent", "My Crawler")
	opener = urllib.request.build_opener()
	f = opener.open(request)
	#f = urllib.request.urlopen(url)
	st = f.read().decode('utf-8');
	parse_ref = Parse_references()
	parse_ref.feed(st)
	print('CVE ID:  ',parse.get_cve_id())
	print('DESCRIPTION: ',parse_desc.get_description())
	print('IMPACT: ',parse_impt.get_impact())
	print('SOLUTIONS: ',parse_sol.get_solution())
	print('REFERENCES: ',parse_ref.get_references())
	print('PRODUCTS: ',parse.get_products())
	print('ATTACK FROM: ',parse.get_attack_from())
	return 0

		
if __name__ == '__main__':
	main()

