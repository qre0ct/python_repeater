__author__ = 'abhinav.chourasia'

##############################################################################################################################################
import os
from libmproxy import flow, proxy, controller
from libmproxy.proxy.server import ProxyServer
from libmproxy.protocol.http import decoded
import time
import requests
import pickle
from configobj import ConfigObj
##############################################################################################################################################


##############################################################################################################################################
# request separator used as a separator marker in the human readable request text files that would be logged. So each request is separated with 
# this marker in the text file. CONFIG_FILE is used to specify the domains that need to be logged etc. 
requestSeparator = "*********************************************************************************************************************************"
CONFIG_FILE = 'config.cfg'
moreConfig = None

# ----------------------------------------------------------------------------------------------------------------------------------------
# global method used to display debug messages when the debug section is true in the config file.
def debug(message):
	if moreConfig['display']['debug'] == 'true':
		print message
# ----------------------------------------------------------------------------------------------------------------------------------------


##############################################################################################################################################


##############################################################################################################################################
# The class that makes use of mitmproxy and logs all requests. 
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
	# we read the target domain from the config file and comapre the requests coming from the device. If it's a match we format those requests 
	# and write it out in the human readable text file. Also at the same time we also dump out the request in the pickle file by calling the 
	# serializeRequestComponents()
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

		# matching the domain read from the config file
		if (req.headers["host"][0] in self.targetDomain):
			self.requestNumber = self.requestNumber + 1
			
			debugMessage = "\nPrinting the request in a more refined fashion and in an output file" + str(assembledRequest)
			debug(debugMessage)
			debugMessage = "\nLogging the request..."
			debug(debugMessage)
			
			# the whole file r/w operation can be put in a common class and accessed form there for better modularity of the code
			# left for a later version
			
			# dumping the file in a pcikle file - the .raw file on the disk
			self.serializeRequestComponents(req)
			try:
				# writing out the requests with the request number in the human readable text file
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
	# the function that dumps the requests in a pickle file - the .raw files on the disk
	def serializeRequestComponents(self, serializeThisRequest):
		debugMessage = "\nRequestLogger Class --> serializeRequestComponents() --> Serializing the Raw Request now using Pickle..."
		debug(debugMessage)

		try :
			# writing out the pickle file
			self.myRawFile = open(self.currentRawFile, "ab")
			
			debugMessage = "\n\nRequestLogger Class --> serializeRequestComponents() --> try {} --> Raw File opened !"
			debug(debugMessage)

			# attaching the request number with each component of each request. The logic is - so that when the user wants a certain request to be 
			# tampered or repeated, we are not really dealing with the human readable text file. (The human readable text file is used only for
			# the case when the user wants to see all the logged requests or when the user wants to actually take a look manually at the requests 
			# from the logs - so he can just goto the folder and read the text files using a text editor.) Instead we pick up all entities of the 
			# request number that the user chose from the pickle file and form a dictionary out of it and then play around with as required.
			requestPort = "port # " + str(self.requestNumber)
			requestScheme = "scheme # " + str(self.requestNumber)
			requestMethod = "method # " + str(self.requestNumber)
			requestPath = "path # " + str(self.requestNumber)
			requestHeaders = "headers # " + str(self.requestNumber)
			requestQueryParams = "query_params # " + str(self.requestNumber)
			requestBody = "request_body # " + str(self.requestNumber)
			
			# creating the dictionary object to be finally dumped out on the disk
			self.rawRequestObject.update({
				requestPort : serializeThisRequest.port,
				requestScheme : serializeThisRequest.scheme,
				requestMethod : serializeThisRequest.method,
				requestPath : serializeThisRequest.get_path_components(),
				requestHeaders : serializeThisRequest.headers,
				requestQueryParams : serializeThisRequest.get_query(),
				requestBody : serializeThisRequest.get_decoded_content()
				})

			# dumping out the raw requests file as .raw files on the disk
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
# handles all the repeater stuff and the modification of the request stuff.
class RepeaterModule(RequestLogger):

	# ----------------------------------------------------------------------------------------------------------------------------------------
	def __init__(self, requestLoggerObject = None, textFile = None, pickleFile = None):
		debugMessage = "\nRepeaterModule class --> init() --> Repeater module kickoff !!"
		debug(debugMessage)

		if(requestLoggerObject is not None): 
			# meaning -> the user has chosen to start a fresh logging session and not read from a previously logged session
			self.numberOfRequestsCaptured = requestLoggerObject.requestNumber

			# reanaming the text and raw files to include the number of requests captured as part of the file name itself. 
			# this is a hack around to help the case where we need to process the previously logged requests.
			newCurrentFileName = os.path.splitext(requestLoggerObject.currentFile)[0] + "_" + str(requestLoggerObject.requestNumber) + ".txt"
			newCurrentRawFileName = os.path.splitext(requestLoggerObject.currentRawFile)[0] + "_" + str(requestLoggerObject.requestNumber) + ".raw"
			os.rename(requestLoggerObject.currentFile, newCurrentFileName)
			os.rename(requestLoggerObject.currentRawFile, newCurrentRawFileName)

			if (self.numberOfRequestsCaptured == 0):
				print "\n\nNo requests were captured to show/replay !!"
				exit(1)
			
			self.currentFileToProcess = newCurrentFileName
			self.rawRequestFile = newCurrentRawFileName

		else:
			# meaning -> the user has chosen to replay the request from a previously logged session
			self.currentFileToProcess = textFile
			self.rawRequestFile = pickleFile
			# finding the number of requests captured by reading it from the file name itself. 
			self.numberOfRequestsCaptured = int(textFile[textFile.rfind("_")+1:textFile.rfind(".")])
			if(self.numberOfRequestsCaptured == 0):
				print "\n\nThe selected log file has zero requests captured to show/replay !!"
				exit(1)
		
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

		# taking user input for choosing whether to show all requests or choose a certain request to play around with
		print "\n\n1.View All Requests \n2.Choose one to repeat "
		choice = input("\nEnter the corresponding number : ")
		print "\n"
		if(choice > 2 or choice < 1):
			print "\nInvalid choice !\n\n"
			exit(1)
		if(choice <=2 and choice >=1):
			# the choice selects the respective function
			self.options[choice]()

		debugMessage = "\nRepeaterModule class --> finished showOptions()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	# to show all the requests captured in the current/previously logged session. It simply reads the requests file line by line and dumps it
	# out on the terminal
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
	# if the user chooses a certain request instead of saying show all the requests. 
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
			# the user choice is taken and sent to the requestMaker() which handles displaying and tampering of the selceted request
			self.requestMaker(choice)
		
		debugMessage = "\nRepeaterModule class --> finished chooseRequest()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	# depending on the user's choice the respective fields are taken from the pickle (.raw) file and a dictionary is made out of it. Now it is
	# the elements of this dictionary that is diplayed to the user as different parts of the request and used when the user wants to tamper with
	# any of it. 
	def requestMaker(self, requestNumber):
		debugMessage = "\nRepeaterModule class --> requestMaker() --> Preparing the request object in requestMaker !"
		debug(debugMessage)
		
		totalNoOfParams = 0
		reqCompoContainer = {} # contains all of the requests that were dumped in the pickle file. 
		userEditContainer = {}
		headersDic = {}
		queryParamsDic = {}

		try:
			myFile = open(self.rawRequestFile, "rb")
			
			debugMessage = "\nRepeaterModule class --> requestMaker() --> try {} --> Raw request file opened to load the pickelized requests"
			debug(debugMessage)

			while 1:
				try:
					# loading back the pickle file into the respective dictionary
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

			# dictionary containing data of request chosen by user. Copying out from the requestCompoContainer dictionary only those parameters that
			# match the user choice. This is the final dictionary that contains the request as per user's choice and this is what would be modified
			# if the user chooses to edit the request or simply repeat it wihout editing. 
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
			print "\n7. Request Body :" + str(reqCompoContainer.get(request_bodyKey))

			print "\n\nTamper components ? (Y/N)\nY - Yes, tamper it !\nN - No, Just repeat the selected request"
			choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")
			
			if (choice.lower() == 'y' ):
				# passing the user chosen request dictionary to tamperData() to edit the parameters of the request
				self.tamperData(userEditContainer)
			
			else: 
				if (choice.lower() == 'n'):
					debugMessage = "\nCalling the request send function ...."
					debug(debugMessage)

					print "\njust repeating the selected request without any tampering"
					# passing the user chosen request dictionary to sendRequest() to simply repeat the request
					self.sendRequest(userEditContainer)
				
				else:
					print "\nInvalid choice !\n\n"
					exit(1)

			if not myFile.closed:
				myFile.close()

			print "\n\nWant to replay another request ?"
			choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")
			
			if (choice.lower() == 'y' ):
				self.chooseRequest()
			
			else:
				if(choice.lower() == 'n' ): 
					print "\nThanks for using the script... more functionality enroute !\n\n"
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
	# holds the user chosen requests dictionary passed from the requestMaker()
	def tamperData(self, dataToTamperContainer):
		debugMessage = "\nRepeaterModule class --> tamperData()"
		debug(debugMessage)
		debugMessage = "Tampering data now !" + str(dataToTamperContainer)
		debug(debugMessage)

		try :
			while 1: # to allow user to tamper the request as many times as he wants to
				componentSize = 0
				genericCounter = 0
				newKey = ""
				newValue = ""

				choice = input("\nEnter the component number to tamper (1-7) ")
				# the entire request has been broken into 7 components which are being handled individually below.
				# each of these cmoponents has options to add a new part to it or edit an existing one depending on the user's choice again. 
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
							if (componentSize != 0):
								debugMessage = "\nEnter position to insert (Valid is 1 - " + str(componentSize) + "): "
								choice = input(debugMessage)
								
								if(choice >=1 and choice <= componentSize):
									newValue = raw_input("\nEnter the parameter you want to add: ")
									dataToTamperContainer.get('requestPath').insert(choice - 1, newValue)
									print "\nRequest updated"
								
								else:
									print "\n\nInvalid choice !"
									exit(1)

							else :
								debugMessage = "\nSelection empty ! You can insert only at position 1 "
								newValue = raw_input("\nEnter the parameter you want to add: ")
								dataToTamperContainer.get('requestPath').insert(0, newValue)
								print "\nRequest updated"

						else:
							if(choice.lower() == 'n'):
								if (componentSize == 0):
									print "\nNothing to edit as of now. The selcetion is empty. You may want to add something before you can edit !"
									continue

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
					elif(choice == 5):
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
								if (componentSize == 0):
									print "\nNothing to edit as of now. The selcetion is empty. You may want to add something before you can edit !"
									continue

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
					elif(choice == 6):
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
								if (componentSize == 0):
									print "\nNothing to edit as of now. The selcetion is empty. You may want to add something before you can edit !"
									continue

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

					# handling body parameters
					elif(choice == 7):
						debugMessage = "\nBody parameters component"
						debug(debugMessage)

						genericCounter = 0
						componentSize = len(dataToTamperContainer.get('requestBody'))
						print "\nThe request body as one whole entity is \n"
						
						debugMessage = "\nThe body part of the request is always treated as a string by mitmproxy. Hence needs to be handled accordingly" 
						debugMessage = debugMessage + str(type(dataToTamperContainer.get('requestBody')))
						debug(debugMessage)

						print str(dataToTamperContainer.get('requestBody'))

						print "\n\nAdd additional body parameters here ?\nY - Yes, add !\nN - No, tamper existing"
						choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")

						if (choice.lower() == 'y' ):
							newValue = raw_input("\nValue :")
							
							if (componentSize == 0):
								debugMessage = str(newValue)
							
							else:
								debugMessage = str(dataToTamperContainer.get('requestBody')) + str(newValue)
							
							dataToTamperContainer.update({'requestBody': debugMessage})
							print "\n\nRequest updated"

						else:
							if(choice.lower() == 'n'):
								if (componentSize == 0):
									print "\nNothing to edit as of now. The selcetion is empty. You may want to add something before you can edit !"
									continue

								debugMessage = "\nNo separate parameters in the body. You need to edit the entire body itself. You may copy paste ! "
								choice = raw_input(debugMessage)
								dataToTamperContainer.update({'requestBody': choice})
								print "\n\nRequest updated"						
							
							else:
								print "\n\nInvalid choice !"
								exit(1)
					# end of if(choice == 7)

					# handling port edit
					elif(choice == 1):
						debugMessage = "\nRequest port component"
						debug(debugMessage)
						
						print "\nThe request is currently directed on port number: " + str(dataToTamperContainer.get('requestPort'))
						newValue = input("\nEnter the new port number you want to send it on: ")
						dataToTamperContainer.update({'requestPort':newValue})
						print "\n\nRequest updated"
					# end of if(choice == 1)

					# handling scheme edit
					elif(choice == 2):
						debugMessage = "\nRequest scheme component"
						debug(debugMessage)

						print "\nThe request is currently directed with scheme: " + str(dataToTamperContainer.get('requestScheme'))
						newValue = raw_input("\nEnter the new scheme you want to send it with: ")
						dataToTamperContainer.update({'requestScheme':newValue})
						print "\n\nRequest updated"
					# end of if(choice == 2)

					# handling method edit
					elif(choice == 3):
						debugMessage = "\nRequest method component"
						debug(debugMessage)

						print "\nThe request is currently directed with method: " + str(dataToTamperContainer.get('requestMethod'))
						newValue = raw_input("\nEnter the new method you want to use to send it: ")
						dataToTamperContainer.update({'requestMethod':newValue})
						print "\n\nRequest updated"
					# end of if(choice == 3)

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
		# end of try {}
		except ValueError:
			debugMessage = "\nRepeaterModule class --> tamperData() --> except {} "
			debug(debugMessage)

			print "\nPositive integer to be entered where and when required !! "
			exit(1)

		# finally when the user is done with all sorts of palying with the different components of the request, the updated dictionary is sent to 
		# the sendRequest() to finally send the request and display the response. 
		self.sendRequest(dataToTamperContainer)

		debugMessage = "\nRepeaterModule class --> finished tamperData()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	# after the user has editted the request and finalized that he wants to send the request, the dictionary containing the updated components
	# is sent to the below function. The below function takes the dictionary and extracts every single component from it to form a request in 
	# terms of the Requests library. Then the Requests library is finally used to send the request and read/display the response. 
	def sendRequest(self, sendThisRequest):
		debugMessage = "\nRepeaterModule class --> sendRequest()"
		debug(debugMessage)

		queryParamsPayload = {}
		headersPayload = {}
		genericCounter = 0
		componentLength = 0
		contentLengthHeaderKey = "Content-Length"
		contentLengthHeaderVal = 0
		bodyPresentFlag = 0
		reqMethod = str(sendThisRequest.get('requestMethod'))

		print "\nFinal request being sent now is :\n"
		print "\n1. Port :" + str(sendThisRequest.get('requestPort'))
		print "\n2. Scheme :" + str(sendThisRequest.get('requestScheme'))
		print "\n3. Method :" + str(sendThisRequest.get('requestMethod'))
		reqPath = "/".join(str(e) for e in sendThisRequest.get('requestPath'))
		print "\n4. Path :" + reqPath
		debugMessage = "".join(str(e) for e in sendThisRequest.get('requestHeaders'))
		print "\n5. Headers :" + debugMessage
		qryParams = "".join(str(e) for e in sendThisRequest.get('requestQueryParams'))
		print "\n6. Query Parameters :" + qryParams
		print "\n7. Request Body :" + str(sendThisRequest.get('requestBody'))
		print "\n\nSending the request now ...! "

		# creating the request 
		debugMessage = "\npreparing the request to be sent..."
		debug(debugMessage)

		bodyPresentFlag = 0

		# making the url
		url = str(sendThisRequest.get('requestScheme')) + "://" + str(sendThisRequest.get('requestHeaders')['host'][0]) + ":" + str(sendThisRequest.get('requestPort'))
		url = url + "/" + reqPath
		
		print "\nRequest being fired on the URL : " + url

		# making the headers
		componentLength = len(sendThisRequest.get('requestHeaders'))
		while(genericCounter < componentLength):
			key = str(sendThisRequest.get('requestHeaders').keys()[genericCounter])
			val = str(sendThisRequest.get('requestHeaders')[sendThisRequest.get('requestHeaders').keys()[genericCounter]][0])
			
			debugMessage = "\nKey = " + key + "\nVal = " + val
			debug(debugMessage)

			headersPayload.update({key:val})
			genericCounter = genericCounter + 1

		# adding the content length header for all requests - by default it is set to 0. If there is any content it is updated to the respective content length
		headersPayload.update({contentLengthHeaderKey:contentLengthHeaderVal})

		debugMessage = "\nHeaders dictionary is " + str(headersPayload)
		debug (debugMessage)
		
		#Checking if there was content 
		componentLength = len(sendThisRequest.get('requestBody'))

		debugMessage = "\nSize of body in the GET request is " + str(componentLength)
		debug(debugMessage)

		if(componentLength != 0):
			# content length found - hence updating the content length header
			contentLengthHeaderVal = componentLength
			headersPayload.update({contentLengthHeaderKey:contentLengthHeaderVal})
			bodyPresentFlag = 1

		# making the query params
		genericCounter = 0
		componentLength = len(sendThisRequest.get('requestQueryParams'))
		
		debugMessage = "\nSize of query params = " + str(componentLength)
		debug(debugMessage)

		try:
			if(componentLength != 0):
				
				debugMessage = "\nQuery params found "
				debug(debugMessage)

				while (genericCounter < componentLength):
					key = str(sendThisRequest.get('requestQueryParams').keys()[genericCounter])
					val = str(sendThisRequest.get('requestQueryParams')[sendThisRequest.get('requestQueryParams').keys()[genericCounter]][0]) 

					debugMessage = "\nKey = " + key + "\nVal = " + val
					debug(debugMessage)

					queryParamsPayload.update({key:val})
					genericCounter = genericCounter + 1
				
				debugMessage = "\nPayloads dictionary is " + str(queryParamsPayload)
				debug (debugMessage)

				if(bodyPresentFlag):
					response = requests.request(reqMethod, url, params = queryParamsPayload, headers = headersPayload, data=str(sendThisRequest.get('requestBody')))

				else:
					response = requests.request(reqMethod, url, params = queryParamsPayload, headers = headersPayload)

			else:
				debugMessage = "\nNo query params found "
				debug(debugMessage)

				if(bodyPresentFlag):
					response = requests.request(reqMethod, url, headers = headersPayload, data=str(sendThisRequest.get('requestBody')))
				
				else:
					response = requests.request(reqMethod, url, headers = headersPayload)
		
		except requests.exceptions.ConnectTimeout as e:
			print "\nWhat is it still the 80s...? You have a literally F****** slow internet ! Can't handle it ! Bye !\n\n"
			exit(1)

		except requests.exceptions.ReadTimeout as e:
			print "\nWhat is it still the 80s...? You have a literally F****** slow internet ! Can't handle it ! Bye !\n\n"
			exit(1)

		except requests.exceptions.HTTPError as e:
			print "\nHTTP doesn't like you ! So it killed itself !\n\n"
			exit(1)

		except requests.exceptions.RequestException as e:
			print "\nOh Boy Boy. You hit THE exception ! Somewhere someone passed on the ball to an unknown URL scheme.\nCan't handle it ! Bye "
			print e
			print "\n\n"
			exit(1)
			
		print "\nThe response received for the above request is : \n\n"
		print response.status_code
		for k, v in response.headers.iteritems():
			print k + ": " + v
		print "\n"
		print response.content

		
		debugMessage = "\nRepeaterModule class --> finished sendRequest()"
		debug(debugMessage)
	# ----------------------------------------------------------------------------------------------------------------------------------------
##############################################################################################################################################


##############################################################################################################################################
if __name__ == "__main__":
	# thought of expressing my gratitude and affinity with python :)
	print "\n\n-- SINCE THE BEGGINGING OF THE AGES THE HUMAN AND THE PYTHON HAVE BEEN LONG RELATED TO EACH OTHER AND THEY HAVE KNOWN TO CO-EXIST IN A SYMBIOTIC "
	print "TIGHTLY COUPLED RELATIONSHIP THAT HAS OFTEN HELPED BOTH THE SPECIES EVOLVE OVER TIME !"
	print "Our find means that humans were more organized and had the capacity for abstract thinking at a much earlier point in history than we have previously assumed !! "

	moreConfig = ConfigObj(CONFIG_FILE)
	choice = 'n'
	counter = 0
	humanRequestFound = None
	pythonRequestFound = None
	humanLogDict = {}
	pythonLogDict = {}

	# reading the dir to figure out if there is even 1 requests file - both the human readable text file and pickle .raw file present. If yes, we show the user
	# that there are preveiosly logged sessions alrady present and if the user would want to use them or start afresh. 
	for file in os.listdir("."):
		if file.endswith(".txt"):
			debugMessage = str(file)
			debug(debugMessage)
			print "\nhuman found"
			humanRequestFound = True
			break
			
	for file in os.listdir("."):
		if file.endswith(".raw"):
			debugMessage = str(file)
			debug(debugMessage)
			print "python found"
			pythonRequestFound = True
			break
		
	if(humanRequestFound and pythonRequestFound):
		debugMessage = "\nYEPPIKKKAAAEE babae....!! "
		debug(debugMessage)

		print "\nPreviously logged sessions exist. Repeat from them ?\nY - Yes, choose an existing session to play with !\nN - No, start fresh !"
		choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")

		if (choice.lower() == 'y'):
			debugMessage = "\nChoosing from existing logged sessions"
			debug(debugMessage)

			print "\nBelow logged requests exist:\n"
			
			# making a dictionary to itemize the previous log files (both text and .raw) present and show to the user. So not when the user chooses one 
			# to replay, the corresponding file can be simply read and processed.
			for file in os.listdir("."):
				if file.endswith(".txt"):
					counter = counter + 1
					print str(counter) + ". " + str(file)
					humanLogDict.update({counter:str(file)})

			counter = 0
			for file in os.listdir("."):
				if file.endswith(".raw"):
					counter = counter + 1
					pythonLogDict.update({counter:str(file)})

			choice = input("\nEnter log number to play with: ")
			
			# if it is the previously logged files being read the RequestLogger module need not be called at all. We can directly call the RepeaterModule
			# passing it the text file chosen by the user and the correspondong .raw file. 
			repMod = RepeaterModule(None, humanLogDict[humanLogDict.keys()[choice - 1]], pythonLogDict[pythonLogDict.keys()[choice - 1]])
			repMod.showOptions()

		elif(choice.lower() == 'n'):
			choice = "n"
		
		else:
			print "\n\nInvalid choice !"
			exit(1)	

	if(choice.lower() == 'n'):
		# starting a new session afresh in case the user chooses to do so instead of reading from previously existing (if any) request logs
		print "\nStarting new session afresh..."
		print "\n\nCtrl+C to stop logging requests and proceed with the REPEATER !! "
		config = proxy.ProxyConfig(
			port=8080,
			# use ~/.mitmproxy/mitmproxy-ca.pem as default CA file.
			cadir="~/.mitmproxy/"
		)
		
		state = flow.State()
		server = ProxyServer(config)
		reqLog = RequestLogger(server)
		reqLog.run()

		repMod = RepeaterModule(reqLog)
		repMod.showOptions()
	
##############################################################################################################################################