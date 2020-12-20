from burp import IBurpExtender, IHttpListener, IMessageEditorTab, IMessageEditorTabFactory

http_proxy = "http://127.0.0.1:8080"
https_proxy = "http://127.0.0.1:8080"
ftp_proxy = "http://127.0.0.0.1:8080"

proxyDict = {"http":http_proxy,"https":https_proxy,"ftp":ftp_proxy}

import requests

import json

requests.packages.urllib3.disable_warnings()

decryptor = "https://127.0.0.1/api/ext3-pgp-decrypt"
encryptor = "https://127.0.0.1/api/ext3-pgp-encrypt"

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):

	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()
		callbacks.registerHttpListener(self)
		callbacks.setExtensionName("Burp Encrypter and Decrypter")
		callbacks.registerMessageEditorTabFactory(self)
	
	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

		if toolFlag != self.callbacks.TOOL_REPEATER and toolFlag != self.callbacks.TOOL_SCANNER and toolFlag != self.callbacks.TOOL_EXTENDER:
			return
		
		if messageIsRequest:
			request = messageInfo.getRequest()
			requestHTTPService = messageInfo.getHttpService();
			requestInfo = self.helpers.analyzeRequest(requestHTTPService,request)

			captured_headers = requestInfo.getHeaders()
			body_offset = requestInfo.getBodyOffset()
			body_bytes = request[body_offset:]		
			body = self.helpers.bytesToString(body_bytes)
			json_data = body
			print "[*] Printing json_data:"
			print json_data
			
			for headers in captured_headers:
				if "127.0.0.1" in headers:
					flag = True

			if flag:
				print "[*] Starting Script"

				encrypt = requests.post(encryptor, data=json_data)
				print "[*} Printing encrypted value:"
				#print encrypt -> This prints response code.
				print encrypt.text

				new_body = encrypt.text
			
			updatedRequest = self.helpers.buildHttpMessage(captured_headers, new_body)
			messageInfo.setRequest(updatedRequest)

	def createNewInstance(self, controller, editable):
		# create a new instance of our custom editor tab
		return YourOwnTab(self, controller, editable)

class YourOwnTab(IMessageEditorTab):
	def __init__(self, extender, controller, editable):
		self._extender = extender
		self._editable = editable
		
		# create an instance of Burp's text editor, to display our decrypted data
		self._txtInput = extender.callbacks.createTextEditor()
		self._txtInput.setEditable(editable)
		

	def getTabCaption(self):
		return "PGP Tab"
		
	def getUiComponent(self):
		return self._txtInput.getComponent()
		
	def isEnabled(self, content, isRequest):
		# enable this tab for requests containing a data parameter
		return isRequest 
		
	def setMessage(self, content, isRequest):
		if content is None:
			# clear our display
			self._txtInput.setText(None)
			self._txtInput.setEditable(False)
		
		else:
			requestInfo = self._extender.helpers.analyzeRequest(content) 
			captured_headers = requestInfo.getHeaders() 				 
			body = content[requestInfo.getBodyOffset():]				 
			body = self._extender.helpers.bytesToString(body)			 

			plainText = ""
					
			if "BEGIN PGP MESSAGE" in body:
				plainText = "Decryption code"
				# If the body contains the "BEGIN PGP MESSAGE" then we can assume its cipher text and will want to decrypt it
				# Perform Decryption code here and assign it to plainText
				decrypt = requests.post(decryptor, data=body)
				print "[*] Decrypt value:"
				#print decrypt
				print decrypt.text

				plainText = decrypt.text

			else:
				plainText = "Request is not a PGP message, do not need to decrypt in custom tab"
				self._txtInput.setEditable(False) # Since it does not need this tab to do anything we can disable

			plainText = self._extender.helpers.stringToBytes(plainText)
			
			self._txtInput.setText(plainText) # this is the code used to set the text in the custom tab
			self._txtInput.setEditable(True) # enabling it to be editable
		
		self._currentMessage = content
	

	def getMessage(self):
		if self._txtInput.isTextModified():
			content = self._currentMessage
			requestInfo = self._extender.helpers.analyzeRequest(content) 
			captured_headers = requestInfo.getHeaders() 				 
			body = content[requestInfo.getBodyOffset():]				 
			body = self._extender.helpers.bytesToString(body)			 
			
			# Retrieve the latest text from the custom request tab
			textFromCustomTab = self._extender.helpers.bytesToString(self._txtInput.getText())
			
			# Assigned new PGP cipherText to variable cipherText
			print "[*]Modified data in Custom tab:"
			print textFromCustomTab

			#encrypt2 = requests.post(encryptor, data=textFromCustomTab)
			#print encrypt -> This prints response code.
			print "[*] Created PGP from custom tab(mod value):"
			#print encrypt2.text
			
			cipherText = textFromCustomTab

			# Store a copy of the updated [IHttpRequestResponse] object
			self._currentMessage = self._extender.helpers.buildHttpMessage(captured_headers, cipherText)

			# Return the updated [IHttpRequestResponse] object to update the original Request body			
			return self._currentMessage
		else:
			return self._currentMessage
	
	def isModified(self):
		return self._txtInput.isTextModified()
	
	def getSelectedData(self):
		return self._txtInput.getSelectedText()
		
