# python_repeater
Something similar to Burp's repeater. I know as of now, it might sound like re-inventing the wheel and that too a 
pretty bad one compared to it's evolved offsprings, but this is just a part of a bigger project that would aim 
at automating mobile appsec assessments. 

For now to be able to use the repeater, all you need is mimtproxy python module installed. Once you are there, 
install the mitmproxy certificate in your real/emulator mobile device. Kickoff the script and start playing around
with it. The script itself is pretty verbose. Once the script is running, you can start off any app on your device
and all the requests you make through that app, will be logged in your current working directory (which can be later
read directly as well). Once done, pass on a Ctrl+C interrupt to the script and follow the verbose comments. 
