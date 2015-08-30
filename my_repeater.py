__author__ = 'abhinav.chourasia'

##############################################################################################################################################
import os
from libmproxy import flow, proxy, controller
from libmproxy.proxy.server import ProxyServer
from libmproxy.protocol.http import decoded
import time
import pickle
from configobj import ConfigObj
##############################################################################################################################################


##############################################################################################################################################
requestSeparator = "****************************************************************************************************"
CONFIG_FILE = 'config.cfg'
moreConfig = None

# ----------------------------------------------------------------------------------------------------------------------------------------
def debug(message):
	if moreConfig['display']['debug'] == 'true':
		print message
# ----------------------------------------------------------------------------------------------------------------------------------------


##############################################################################################################################################


##############################################################################################################################################
class RequestLogger(controller.Master):
	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def __init__(self, server):
		controller.Master.__init__(self, server)
		
		debugMessage = "\n RequestLogger Class --> init()"
		debug(debugMessage)

		self.myFile = None
		self.requestNumber = 0
		self.timeStamp = time.strftime("%d%m%Y_%H%M%S")
		self.currentFile = "Requests_as_on_" + self.timeStamp + ".txt"
		self.currentRawFile = "raw_file_on_" + self.timeStamp + ".raw"
		self.myFile = open(self.currentFile, "w")
		self.myRawFile = open(self.currentRawFile, "wb")
		global requestSeparator
		self.requestSeparator = requestSeparator 
		self.rawRequestObject = {}
		self.targetDomain = []

		debugMessage = "\nRequestLogger Class --> finished init()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------


	# ----------------------------------------------------------------------------------------------------------------------------------------
	def run(self):
		debugMessage = "\nRequestLogger Class --> run()"
		debug(debugMessage)

		try:
			debugMessage = "\nRequestLogger Class --> run() --> try {}"
			debug(debugMessage)
			
			return controller.Master.run(self)
		
		except KeyboardInterrupt:
			debugMessage = "\nRequestLogger Class --> run() --> except{} KeyboardInterrupt !"
			debug(debugMessage)

			if not self.myFile.closed :
				self.myFile.close()
				
				if (self.myFile.closed):
					debugMessage = "\nOpen file now closed"
					debug(debugMessage)

			self.shutdown()

		debugMessage = "\nRequestLogger Class --> finished run()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def handle_request(self, flow):
		debugMessage = "\nRequestLogger Class --> handle_request()"
		debug(debugMessage)

		req = flow.request
		assembledRequest = req.assemble()

		debugMessage = "\nthe assembled request is \n" + str(assembledRequest)
		debugMessage = debugMessage + "\nthe host is \n" + str(req.headers["host"][0])
		debugMessage = debugMessage + "\nget_path_components \n" + str(req.get_path_components())
		debugMessage = debugMessage + "\nget_query \n" + str(req.get_query())
		debugMessage = debugMessage + "\nget_decoded_content is \n" + str(req.get_decoded_content())
		debugMessage = debugMessage + "\nThe request headers are \n" + str(req.headers)
		debugMessage = debugMessage + "\npath is \n" + str(req.path)
		debugMessage = debugMessage + "\nscheme is \n" + str(req.scheme)
		debugMessage = debugMessage + "\nurl is \n" + str(req.url)
		debug(debugMessage)
		
		self.targetDomain = moreConfig['target'].values()

		if (req.headers["host"][0] in self.targetDomain):
			self.requestNumber = self.requestNumber + 1
			
			debugMessage = "\nPrinting the request in a more refined fashion and in an output file" + str(assembledRequest)
			debug(debugMessage)
			debugMessage = "\nLogging the request..."
			debug(debugMessage)
			
			# the whole file r/w operation can be put in a common class and accessed form there for better modularity of the code
			# left for a later version
			
			self.serializeRequestComponents(req)
			try:
				self.myFile = open(self.currentFile, "a")
				
				debugMessage = "\nRequestLogger Class --> handle_request --> try {} --> Requests File opened !"
				debug(debugMessage)

				if (self.requestNumber == 1):
					self.myFile.write (self.requestSeparator)
				self.myFile.write ("\nRequest # " + str(self.requestNumber) + "\n" + "Port: " + str(req.port) + "\n" + assembledRequest )
				if (req.method != "GET"):
					self.myFile.write ("\r\n\r\n")
				self.myFile.write (self.requestSeparator + "\n")

			except IOError:
				debugMessage = "\nRequestLogger Class --> handle_request --> except {}"
				debug(debugMessage)
				
				print "\n\nThere was an error r/w -ing the file !! \n\n"
			
			finally:
				debugMessage = "\nRequestLogger Class --> handle_request --> finally {}"
				debug(debugMessage)
				
				self.myFile.close()

				if (self.myFile.closed):
					debugMessage = "\nRequestLogger Class --> handle_request --> finally {} --> file closed successfully"
					debug(debugMessage)
				
		flow.reply()

		debugMessage = "\nRequestLogger Class --> finished handle_request()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def serializeRequestComponents(self, serializeThisRequest):
		debugMessage = "\nRequestLogger Class --> serializeRequestComponents() --> Serializing the Raw Request now using Pickle..."
		debug(debugMessage)

		try :
			self.myRawFile = open(self.currentRawFile, "ab")
			
			debugMessage = "\n\nRequestLogger Class --> serializeRequestComponents() --> try {} --> Raw File opened !"
			debug(debugMessage)

			requestPort = "port # " + str(self.requestNumber)
			requestScheme = "scheme # " + str(self.requestNumber)
			requestMethod = "method # " + str(self.requestNumber)
			requestPath = "path # " + str(self.requestNumber)
			requestHeaders = "headers # " + str(self.requestNumber)
			requestQueryParams = "query_params # " + str(self.requestNumber)
			requestBody = "request_body # " + str(self.requestNumber)
			
			self.rawRequestObject.update({
				requestPort : serializeThisRequest.port,
				requestScheme : serializeThisRequest.scheme,
				requestMethod : serializeThisRequest.method,
				requestPath : serializeThisRequest.get_path_components(),
				requestHeaders : serializeThisRequest.headers,
				requestQueryParams : serializeThisRequest.get_query(),
				requestBody : serializeThisRequest.get_decoded_content()
				})

			pickle.dump (self.rawRequestObject, self.myRawFile)
			
			debugMessage = "\nCurrent request picklized .... pickle dumped to raw file"
			debug(debugMessage)
		
		except IOError:
			debugMessage = "\n\nRequestLogger Class --> serializeRequestComponents() --> except {}"
			debug(debugMessage)

			print "\n\nThere was an error r/w -ing the file !! \n\n"
		
		finally:
			debugMessage = "\n\nRequestLogger Class --> serializeRequestComponents() --> finally {}"
			debug(debugMessage)

			self.myRawFile.close()

			if (self.myRawFile.closed):
				debugMessage = "\n\nRequestLogger Class --> serializeRequestComponents() --> finally {} --> raw pickle file closed successfully"
				debug(debugMessage)

		debugMessage = "\nRequestLogger Class --> finished serializeRequestComponents()"
		debug(debugMessage)		
	# ----------------------------------------------------------------------------------------------------------------------------------------
##############################################################################################################################################



##############################################################################################################################################
class RepeaterModule(RequestLogger):

	# ----------------------------------------------------------------------------------------------------------------------------------------
	def __init__(self, requestLoggerObject):
		debugMessage = "\nRepeaterModule class --> init() --> Repeater module kickoff !!"
		debug(debugMessage)

		self.numberOfRequestsCaptured = requestLoggerObject.requestNumber

		if (self.numberOfRequestsCaptured == 0):
			print "\n\nNo requests were captured to show/replay !!"
			exit(1)
		
		self.currentFileToProcess = requestLoggerObject.currentFile
		self.rawRequestFile = requestLoggerObject.currentRawFile
		
		self.options = {
			1:self.viewAllRequests,
			2:self.chooseRequest,
		}
		print "\nYou have " + str(self.numberOfRequestsCaptured) + " number of requests captured in this session as per your filter \n"
		print "You can find them in the file " + self.currentFileToProcess + " in your current working directory."

		debugMessage = "\nRepeaterModule class --> finished init()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def showOptions(self):
		debugMessage = "\nRepeaterModule class --> showOptions()"
		debug(debugMessage)

		# taking user input for choosing which app to test !
		print "\n\n1.View All Requests \n2.Choose one to repeat "
		# choosing the right method depending on user choice 
		choice = input("\nEnter the corresponding number : ")
		print "\n"
		if(choice > 2 or choice < 1):
			print "\nInvalid choice !\n\n"
			exit(1)
		if(choice <=2 and choice >=1):
			self.options[choice]()

		debugMessage = "\nRepeaterModule class --> finished showOptions()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def viewAllRequests(self):
		debugMessage = "\nRepeaterModule class --> viewAllRequests()"
		debug(debugMessage)

		print "\nShowing all requests captured in your current session\n\n"
		try:
			myFile = open(self.currentFileToProcess, "r")
			
			debugMessage = "\nRepeaterModule class --> viewAllRequests() --> try {} --> Human readable Requests file opened !"
			debug(debugMessage)

			for line in myFile.readlines():
				print line

			if not myFile.closed:
				myFile.close()
			self.chooseRequest()

		except IOError:
			debugMessage = "\nRepeaterModule class --> viewAllRequests() --> except {}"
			debug(debugMessage)

			print "\n\nThere was an error r/w -ing the file !! \n\n"
		
		finally:
			debugMessage = "\nRepeaterModule class --> viewAllRequests() --> finally {}"
			debug(debugMessage)

			myFile.close()
			
			if (myFile.closed):
				debugMessage = "\nOpened Raw file successfully closed !"
				debug(debugMessage)	

		debugMessage = "\nRepeaterModule class --> finished viewAllRequests()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def chooseRequest(self):
		debugMessage = "\nRepeaterModule class --> chooseRequest()"
		debug(debugMessage)

		print "\nWhich request number to replay ? "
		print "\nvalid options are 1 to " + str(self.numberOfRequestsCaptured)
		choice = input("\nEnter the corresponding number : ")
		print "\n"

		if(choice > self.numberOfRequestsCaptured or choice < 1):
			print "\nInvalid choice !\n\n"
			exit(1)
		
		if(choice <= self.numberOfRequestsCaptured and choice >=1):
			self.requestMaker(choice)

		debugMessage = "\nRepeaterModule class --> finished chooseRequest()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def requestMaker(self, requestNumber):
		debugMessage = "\nRepeaterModule class --> requestMaker() --> Preparing the request object in requestMaker !"
		debug(debugMessage)
		
		totalNoOfParams = 0
		reqCompoContainer = {}
		userEditContainer = {}
		headersDic = {}
		queryParamsDic = {}

		try:
			myFile = open(self.rawRequestFile, "rb")
			
			debugMessage = "\nRepeaterModule class --> requestMaker() --> try {} --> Raw request file opened to load the pickelized requests"
			debug(debugMessage)

			while 1:
				try:
					reqCompoContainer.update(pickle.load(myFile))
				except EOFError:
					break # no more data in the file
			
			debugMessage = "\nreqCompoContainer is " + str(reqCompoContainer)
			debug(debugMessage)

			portKey = "port # " + str(requestNumber)
			schemeKey = "scheme # " + str(requestNumber)
			methodKey = "method # " + str(requestNumber)
			pathKey = "path # " + str(requestNumber)
			headersKey = "headers # " + str(requestNumber)
			query_paramsKey = "query_params # " + str(requestNumber)
			request_bodyKey = "request_body # " + str(requestNumber)

			headersDic = reqCompoContainer.get(headersKey)
			queryParamsDic = reqCompoContainer.get(query_paramsKey)

			# dictionary containing data of request chosen by user
			userEditContainer.update({
				'requestPort' : reqCompoContainer.get(portKey),
				'requestScheme' : reqCompoContainer.get(schemeKey),
				'requestMethod' : reqCompoContainer.get(methodKey),
				'requestPath' : reqCompoContainer.get(pathKey),
				'requestHeaders' : headersDic,
				'requestQueryParams' : queryParamsDic,
				'requestBody' : reqCompoContainer.get(request_bodyKey)
				})

			print "\n\nYour chosen request has the following components : "
			print "\n1. Port :" + str(reqCompoContainer.get(portKey))
			print "\n2. Scheme :" + str(reqCompoContainer.get(schemeKey))
			print "\n3. Method :" + str(reqCompoContainer.get(methodKey))
			debugMessage = "/".join(str(e) for e in reqCompoContainer.get(pathKey))
			print "\n4. Path :" + debugMessage
			debugMessage = " ".join(str(e) for e in reqCompoContainer.get(headersKey))
			print "\n5. Headers :" + debugMessage
			debugMessage = " ".join(str(e) for e in reqCompoContainer.get(query_paramsKey))
			print "\n6. Query Parameters :" + debugMessage
			debugMessage = " ".join(str(e) for e in reqCompoContainer.get(request_bodyKey))
			print "\n7. Request Body :" + debugMessage

			print "\n\nTamper components ? (Y/N)\nY - Yes, tamper it !\nN - No, Just repeat the selected request"
			choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")
			
			if (choice.lower() == 'y' ):
				self.tamperData(userEditContainer)
			
			else: 
				if (choice.lower() == 'n'):
					print "\n\nCalling the request send function ....just repeating the selected request without any tampering"
					self.sendRequest()
				
				else:
					print "\nInvalid choice !\n\n"
					exit(1)

			if not myFile.closed:
				myFile.close()

			print "\nWant to replay another request ?"
			choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")
			
			if (choice.lower() == 'y' ):
				self.chooseRequest()
			
			else:
				if(choice.lower() == 'n' ): 
					print "\nThanks for using the script... more functionality enroute !"
					exit(1)
				
				else:
					print "\nInvalid choice !\n\n"
					exit(1)

		except IOError:
			debugMessage = "\nRepeaterModule class --> requestMaker() --> except {} !"
			debug(debugMessage)
			
			print "\n\nThere was an error r/w -ing the file !! \n\n"
		
		finally:
			debugMessage = "\nRepeaterModule class --> requestMaker() --> finally {} !"
			debug(debugMessage)
			
			myFile.close()
			
			if (myFile.closed):
				debugMessage = "\nRepeaterModule class --> requestMaker() --> finally {} --> open file succesfully closed!"
				debug(debugMessage)

		debugMessage = "\nRepeaterModule class --> finished requestMaker()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def tamperData(self, dataToTamperContainer):
		debugMessage = "\nRepeaterModule class --> tamperData()"
		debug(debugMessage)
		debugMessage = "Tampering data now !" + str(dataToTamperContainer)
		debug(debugMessage)

		while 1:
			componentSize = 0
			genericCounter = 0
			newKey = ""
			newValue = ""

			choice = input("\nEnter the component number to tamper (1-7) ")
			
			if (choice >= 1 and choice <= 7):
				
				# handling path component
				if (choice == 4):
					debugMessage = "\nPath component"
					debug(debugMessage)

					componentSize = len(dataToTamperContainer.get('requestPath'))
					
					print "\nParameters of this component are \n"
					while (genericCounter < componentSize):
						print str(genericCounter+1) + "." + str(dataToTamperContainer.get('requestPath')[genericCounter])
						genericCounter = genericCounter + 1 
					
					print "\n\nAdd additional parameters here ?\nY - Yes, add !\nN - No, tamper existing"
					choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")
					
					if (choice.lower() == 'y' ):
						debugMessage = "\nEnter position to insert (Valid is 1 - " + str(componentSize) + "): "
						choice = input(debugMessage)
						
						if(choice >=1 and choice <= componentSize):
							newValue = raw_input("\nEnter the parameter you want to add: ")
							dataToTamperContainer.get('requestPath').insert(choice - 1, newValue)
							print "\nRequest updated"
						
						else:
							print "\n\nInvalid choice !"
							exit(1)
					
					else:
						if(choice.lower() == 'n'):
							debugMessage = "\nEnter parameter number to tamper (Valid is 1 - " + str(componentSize) + "): "
							choice = input(debugMessage)
							
							if(choice >=1 and choice <= componentSize):
								newValue = raw_input("\nEnter the new value: ")
								dataToTamperContainer.get('requestPath')[choice - 1] = newValue
								print "\nRequest updated"
							
							else:
								print "\n\nInvalid choice !"
								exit(1)
						else:
							print "\n\nInvalid choice !"
							exit(1)
				# end of if(choice == 4)

				# handling headers
				if(choice == 5):
					debugMessage = "\nHeader component"
					debug(debugMessage)

					genericCounter = 0
					componentSize = len(dataToTamperContainer.get('requestHeaders'))
					print "\nParameters of this component are \n"
					while (genericCounter < componentSize):
						print str(genericCounter+1) + "." + str(dataToTamperContainer.get('requestHeaders').keys()[genericCounter]) + ": " + str(dataToTamperContainer.get('requestHeaders')[dataToTamperContainer.get('requestHeaders').keys()[genericCounter]]) 
						genericCounter = genericCounter + 1 

					print "\n\nAdd additional headers here ?\nY - Yes, add !\nN - No, tamper existing"
					choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")

					if (choice.lower() == 'y' ):
						newKey = raw_input("\nKey : ")
						newValue = raw_input("\nValue :")
						dataToTamperContainer.get('requestHeaders')[newKey] = [newValue]
						print "\n\nRequest updated"

					else:
						if(choice.lower() == 'n'):
							debugMessage = "\nEnter parameter number to tamper (Valid is 1 - " + str(componentSize) + "): "
							choice = input(debugMessage)
							
							if(choice >=1 and choice <= componentSize):
								newKey = raw_input("\nKey : ")
								newValue = raw_input("\nValue :")
								
								debugMessage = "\n\nthe selected key is " + str(dataToTamperContainer.get('requestHeaders').keys()[choice - 1])
								debug(debugMessage)
								
								del dataToTamperContainer.get('requestHeaders')[dataToTamperContainer.get('requestHeaders').keys()[choice - 1]]
								dataToTamperContainer.get('requestHeaders')[newKey] = [newValue]
								print "\nRequest updated"
							
							else:
								print "\n\nInvalid choice !"
								exit(1)	
						
						else:
							print "\n\nInvalid choice !"
							exit(1)
				# end of if(choice == 5)

				# handling query parameters
				if(choice == 6):
					debugMessage = "\nQuery parameters component"
					debug(debugMessage)

					genericCounter = 0
					componentSize = len(dataToTamperContainer.get('requestQueryParams'))
					print "\nParameters of this component are \n"
					while (genericCounter < componentSize):
						print str(genericCounter+1) + "." + str(dataToTamperContainer.get('requestQueryParams').keys()[genericCounter]) + "= " + str(dataToTamperContainer.get('requestQueryParams')[dataToTamperContainer.get('requestQueryParams').keys()[genericCounter]]) 
						genericCounter = genericCounter + 1

					print "\n\nAdd additional query parameters here ?\nY - Yes, add !\nN - No, tamper existing"
					choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")

					if (choice.lower() == 'y' ):
						newKey = raw_input("\nKey : ")
						newValue = raw_input("\nValue :")
						dataToTamperContainer.get('requestQueryParams')[newKey] = [newValue]
						print "\n\nRequest updated"

					else:
						if(choice.lower() == 'n'):
							debugMessage = "\nEnter parameter number to tamper (Valid is 1 - " + str(componentSize) + "): "
							choice = input(debugMessage)
							
							if(choice >=1 and choice <= componentSize):
								newKey = raw_input("\nKey : ")
								newValue = raw_input("\nValue :")
								
								debugMessage = "\n\nthe selected key is " + str(dataToTamperContainer.get('requestQueryParams').keys()[choice - 1])
								debug(debugMessage)
								
								del dataToTamperContainer.get('requestQueryParams')[dataToTamperContainer.get('requestQueryParams').keys()[choice - 1]]
								dataToTamperContainer.get('requestQueryParams')[newKey] = [newValue]
								print "\nRequest updated"
							
							else:
								print "\n\nInvalid choice !"
								exit(1)	
						
						else:
							print "\n\nInvalid choice !"
							exit(1)
				# end of if(choice == 6)

			# end of if (choice >= 1 and choice <= 7):
			else:
				print "\n\nInvalid choice !"
				exit(1)

			addMore = raw_input("\nTamper more (y/n): ")
			if(addMore.lower() == 'y'):
				continue
			
			else:
				if(addMore.lower() == 'n'):
					break
				
				else:
					print "\n\nInvalid choice !"
					exit(1)

		# enf of while 1:
		self.sendRequest()

		debugMessage = "\nRepeaterModule class --> finished tamperData()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def sendRequest(self):
		print "\n\nSending the request now ...! "
	# ----------------------------------------------------------------------------------------------------------------------------------------
##############################################################################################################################################


##############################################################################################################################################
if __name__ == "__main__":
	
	print "\n\nCtrl+C to stop logging requests and proceed with the REPEATER !! "
	config = proxy.ProxyConfig(
		port=8080,
		# use ~/.mitmproxy/mitmproxy-ca.pem as default CA file.
		cadir="~/.mitmproxy/"
	)
	moreConfig = ConfigObj(CONFIG_FILE)
	state = flow.State()
	server = ProxyServer(config)
	reqLog = RequestLogger(server)
	reqLog.run()
	
	repMod = RepeaterModule(reqLog)
	repMod.showOptions()
##############################################################################################################################################