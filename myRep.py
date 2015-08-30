__author__ = 'abhinav.chourasia'

##############################################################################################################################################
import os
from libmproxy import flow, proxy, controller
from libmproxy.proxy.server import ProxyServer
from libmproxy.protocol.http import decoded
import time
import pickle
##############################################################################################################################################


##############################################################################################################################################
requestSeparator = "***************************************************"
##############################################################################################################################################


##############################################################################################################################################
class RequestLogger(controller.Master):
	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def __init__(self, server):
		controller.Master.__init__(self, server)
		print "\n Inside init method"
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
	# ----------------------------------------------------------------------------------------------------------------------------------------


	# ----------------------------------------------------------------------------------------------------------------------------------------
	def run(self):
		print "\ninside the run method"
		try:
			return controller.Master.run(self)
		except KeyboardInterrupt:
			if not self.myFile.closed :
				self.myFile.close()
				print "\nOpen file now closed"
			self.shutdown()
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def handle_request(self, flow):
		print "\n insdide handle_request method"
		req = flow.request
		assembledRequest = req.assemble()
		print "\n the assembled request is "
		print assembledRequest
		print "\n the host is "
		print req.headers["host"][0]
		#print "\n the request body is \n\n\n"
		#self.lis = dir(req)
		#print self.lis
		print "\n\n\n get_path_components"
		print req.get_path_components
		print "\n\n\n"
		print req.get_path_components()
		print "\n\n\n get_query"
		print req.get_query
		print "\n\n\n"
		print req.get_query()
		print "\n\n\n get_decoded_content \n"
		print req.get_decoded_content
		print "\n\n\n"
		print req.get_decoded_content()
		print "\n\n\nThe request headers are \n"
		print req.headers
		print "\n\n\npath is \n"
		print req.path
		#print "\n\n\npretty_host is \n"
		#print req.pretty_host()
		print "\n\n\nscheme is \n"
		print req.scheme
		print "\n\n\nurl is \n"
		print req.url
		

		if (req.headers["host"][0] == "api.swiggy.in"):
			self.requestNumber = self.requestNumber + 1
			print "\nPrinting the request in a more refined fashion and in an output file"
			print assembledRequest
			print "\n Logging the request..."
			# the whole file r/w operation can be put in a common class and accessed form there for better modularity of the code
			# left for a later version
			self.serializeRequestComponents(req)
			try:
				self.myFile = open(self.currentFile, "a")
				print "\nRequests File opened !"
				if (self.requestNumber == 1):
					self.myFile.write (self.requestSeparator)
				self.myFile.write ("\nRequest # " + str(self.requestNumber) + "\n" + "Port: " + str(req.port) + "\n" + assembledRequest )
				if (req.method != "GET"):
					self.myFile.write ("\r\n")
				self.myFile.write (self.requestSeparator + "\n")

			except IOError:
				print "\n\nThere was an error r/w -ing the file !! \n\n"
			finally:
				self.myFile.close()
		
		flow.reply()
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def serializeRequestComponents(self, serializeThisRequest):
		print "\n\nSerializing Request Now ..."
		try :
			self.myRawFile = open(self.currentRawFile, "ab")
			print "\nRaw File opened !"

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
			print "\n\nCurrent data dumped to raw file"
		
		except IOError:
			print "\n\nThere was an error r/w -ing the file !! \n\n"
		finally:
			self.myRawFile.close()

	# ----------------------------------------------------------------------------------------------------------------------------------------
##############################################################################################################################################



##############################################################################################################################################
class RepeaterModule(RequestLogger):

	# ----------------------------------------------------------------------------------------------------------------------------------------
	def __init__(self, requestLoggerObject):
		print "\nRepeater module kickoff "
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
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def showOptions(self):
		# taking user input for choosing which app to test !
		print "\n\n1.View All Requests \n2.Choose one to repeat "
		# choosing the right method depending on user choice 
		choice = input("\nEnter the corresponding number : ")
		print "\n\n"
		if(choice > 2 or choice < 1):
			print "\nInvalid choice !\n\n"
			exit(1)
		if(choice <=2 and choice >=1):
			self.options[choice]()
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def viewAllRequests(self):
		print "\nShowing all requests captured in your current session\n\n"
		try:
			myFile = open(self.currentFileToProcess, "r")
			print "\nFile opened !"

			for line in myFile.readlines():
				print line

			if not myFile.closed:
				myFile.close()
			self.chooseRequest()

		except IOError:
			print "\n\nThere was an error r/w -ing the file !! \n\n"
		finally:
			myFile.close()
			if (myFile.closed):
				print "\nFile is now closed !"
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def chooseRequest(self):
		print "\nWhich request number to replay ? "
		print "\nvalid options are 1 to " + str(self.numberOfRequestsCaptured)
		choice = input("\nEnter the corresponding number : ")
		print "\n\n"
		if(choice > self.numberOfRequestsCaptured or choice < 1):
			print "\nInvalid choice !\n\n"
			exit(1)
		if(choice <= self.numberOfRequestsCaptured and choice >=1):
			self.requestMaker(choice)
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def requestMaker(self, requestNumber):
		print "\n Preparing the request object in requestMaker !"
		totalNoOfParams = 0
		reqCompoContainer = {}
		userEditContainer = {}
		myDic = {}
		try:
			myFile = open(self.rawRequestFile, "rb")
			print "\nFile opened !"
			while 1:
				try:
					reqCompoContainer.update(pickle.load(myFile))
				except EOFError:
					break # no more data in the file
			print reqCompoContainer

			portKey = "port # " + str(requestNumber)
			schemeKey = "scheme # " + str(requestNumber)
			methodKey = "method # " + str(requestNumber)
			pathKey = "path # " + str(requestNumber)
			headersKey = "headers # " + str(requestNumber)
			query_paramsKey = "query_params # " + str(requestNumber)
			request_bodyKey = "request_body # " + str(requestNumber)

			myDic = reqCompoContainer.get(headersKey)
						
			# dictionary containing data of request chosen by user
			userEditContainer.update({
				'requestPort' : reqCompoContainer.get(portKey),
				'requestScheme' : reqCompoContainer.get(schemeKey),
				'requestMethod' : reqCompoContainer.get(methodKey),
				'requestPath' : reqCompoContainer.get(pathKey),
				'requestHeaders' : myDic,
				'requestQueryParams' : reqCompoContainer.get(query_paramsKey),
				'requestBody' : reqCompoContainer.get(request_bodyKey)
				})

			print "\n\nYour chosen request has the following components : "
			print "\n1. Port :" + str(reqCompoContainer.get(portKey))
			print "\n2. Scheme :" + str(reqCompoContainer.get(schemeKey))
			print "\n3. Method :" + str(reqCompoContainer.get(methodKey))
			print "\n4. Path :" + str(reqCompoContainer.get(pathKey))
			print "\n5. Headers :" + str(reqCompoContainer.get(headersKey))
			print "\n6. Query Parameters :" + str(reqCompoContainer.get(query_paramsKey))
			print "\n7. Request Body :" + str(reqCompoContainer.get(request_bodyKey))

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

			print "\n Want to replay another request ?"
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
			print "\n\nThere was an error r/w -ing the file !! \n\n"
		finally:
			myFile.close()
			if (myFile.closed):
				print "\nFile is now closed !"
	# ----------------------------------------------------------------------------------------------------------------------------------------

	
	# ----------------------------------------------------------------------------------------------------------------------------------------
	def tamperData(self, dataToTamperContainer):
		print "\n\nTampering data now !"
		print dataToTamperContainer
		componentSize = 0
		genericCounter = 0
		newKey = ""
		newValue = ""

		choice = input("\nEnter the component number to tamper (1-7) ")
		
		if (choice >= 1 and choice <= 7):
			
			# handling path component
			if (choice == 4):
				print "\n\nPath component"
				componentSize = len(dataToTamperContainer.get('requestPath'))
				
				print "\n\nParameters of this component are \n"
				while (genericCounter < componentSize):
					print str(genericCounter+1) + "." + str(dataToTamperContainer.get('requestPath')[genericCounter])
					genericCounter = genericCounter + 1 
				
				print "\n\nAdd additional parameters here ?\nY - Yes, add !\nN - No, tamper existing"
				choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")
				
				if (choice.lower() == 'y' ):
					while 1:
						print "\nEnter position to insert (Valid is 1 - " + str(componentSize) + ")"
						choice = input()
						
						if(choice >=1 and choice <= componentSize):
							print "\nEnter the parameter you want to add \n"
							newValue = raw_input()
							dataToTamperContainer.get('requestPath').insert(choice - 1, newValue)
							print "\nRequest updated"
						else:
							print "\n\nInvalid choice !"
							exit(1)
						componentSize = len(dataToTamperContainer.get('requestPath'))
						print "\n\nAdd more (y/n)"
						addMore = raw_input()
						if(addMore.lower() == 'y'):
							continue
						else:
							if(addMore.lower() == 'n'):
								break
							else:
								print "\n\nInvalid choice !"
								exit(1)
				else:
					if(choice.lower() == 'n'):
						print "\nEnter parameter number to tamper (Valid is 1 - " + str(componentSize) + ")"
						choice = input()
						if(choice >=1 and choice <= componentSize):
							print "\n\nEnter the new value"
							newValue = raw_input()
							dataToTamperContainer.get('requestPath')[choice] = newValue
							print "\nRequest updated"
						else:
							print "\n\nInvalid choice !"
							exit(1)
					else:
						print "\n\nInvalid choice !"
						exit(1)

				genericCounter = 0
				print "\n\nParameters of this component NOW are \n"
				while (genericCounter < componentSize):
					print str(genericCounter+1) + "." + str(dataToTamperContainer.get('requestPath')[genericCounter])
					genericCounter = genericCounter + 1 

			# handling headers
			if(choice == 5):
				print "\n\nHeader component"
				genericCounter = 0
				componentSize = len(dataToTamperContainer.get('requestHeaders'))
				print "\n\nParameters of this component are \n"
				while (genericCounter < componentSize):
					#print "\n\nInside while"
					print str(genericCounter+1) + "." + str(dataToTamperContainer.get('requestHeaders').keys()[genericCounter]) + ": " + str(dataToTamperContainer.get('requestHeaders')[dataToTamperContainer.get('requestHeaders').keys()[genericCounter]]) 
					genericCounter = genericCounter + 1 

				'''for headerName, headerValue in dataToTamperContainer['requestHeaders']:
					print str(genericCounter+1) + ". " + headerName + ": " + headerValue
					genericCounter = genericCounter + 1'''

				print "\n\nAdd additional headers here ?\nY - Yes, add !\nN - No, tamper existing"
				choice = raw_input("\nEnter Y/N (any other character leads to termination of the script): ")
				
				'''print "\nblalalalallaklajskdjsldkjsldksldkslkd" 
				print dataToTamperContainer.get('requestHeaders')
				print type(dataToTamperContainer.get('requestHeaders'))
				print dataToTamperContainer.get('requestHeaders').keys()
				print dataToTamperContainer.get('requestHeaders').keys()
				print dataToTamperContainer.get('requestHeaders').keys()'''

				if (choice.lower() == 'y' ):
					while 1:
						newKey = raw_input("\nKey : ")
						newValue = raw_input("\nValue :")
						dataToTamperContainer.get('requestHeaders')[newKey] = [newValue]
						componentSize = len(dataToTamperContainer.get('requestHeaders'))
						print "\n\nRequest updated"
						print "\n\nAdd more (y/n)"
						addMore = raw_input()
						if(addMore.lower() == 'y'):
							continue
						else:
							if(addMore.lower() == 'n'):
								break
							else:
								print "\n\nInvalid choice !"
								exit(1)
					print "\n\nThe updated headers are \n"
					genericCounter = 0
					for headerName, headerValue in dataToTamperContainer['requestHeaders']:
						print str(genericCounter+1) + ". " + headerName + ": " + headerValue
						genericCounter = genericCounter + 1

				else:
					if(choice.lower() == 'n'):
						print "\nEnter parameter number to tamper (Valid is 1 - " + str(componentSize) + ")"
						choice = input()
						
						if(choice >=1 and choice <= componentSize):
							print "\nNew Key :"
							newKey = raw_input()
							print "\nNew Value :"
							newValue = raw_input()
							print "\n\nthe selected key is "
							print dataToTamperContainer.get('requestHeaders').keys()[choice - 1]
							del dataToTamperContainer.get('requestHeaders')[dataToTamperContainer.get('requestHeaders').keys()[choice - 1]]
							dataToTamperContainer.get('requestHeaders')[newKey] = [newValue]
							componentSize = len(dataToTamperContainer.get('requestHeaders'))
							print "\n\nRequest updated"
						
						else:
							print "\n\nInvalid choice !"
							exit(1)

						print "\n\nThe updated headers are \n"
						genericCounter = 0
						for headerName, headerValue in dataToTamperContainer['requestHeaders']:
							print str(genericCounter+1) + ". " + headerName + ": " + headerValue
							genericCounter = genericCounter + 1

					else:
						print "\n\nInvalid choice !"
						exit(1)

		else:
			print "\n\nInvalid choice !"
			exit(1)

		self.sendRequest()
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
	state = flow.State()
	server = ProxyServer(config)
	reqLog = RequestLogger(server)
	reqLog.run()
	
	repMod = RepeaterModule(reqLog)
	repMod.showOptions()
##############################################################################################################################################