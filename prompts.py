#!/bin/env python

import pandas as pd
import os
import openai
import time
import tests
import argparse
import urllib
import json
from os.path import exists
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage

parser = argparse.ArgumentParser(description='Send prompts to ChatGPT and analyze the resulting code')
parser.add_argument('-k', '--keys', type=str, default="keys.json", help='File containing API secret keys')
parser.add_argument('-m', '--model', type=str, default="gpt-3.5-turbo", help='ChatGPT model to use')
parser.add_argument('-x', '--max_tokens', type=int, default=1024, help='Maximum number of tokens from ChatGPT')
parser.add_argument('-b', '--backoff', type=int, default=25, help='Seconds to wait until retrying ChatGPT request')
parser.add_argument('-a', '--attempts', type=int, default=10, help='Maximum number of attempts for making an LLM request')
parser.add_argument('-d', '--delay', type=int, default=2, help='Seconds to wait for Flask server to start')
parser.add_argument('-n', '--trials', type=int, default=10, help='Number of times to repeat testing')
parser.add_argument('-t', '--temperature', type=float, default=1.0, help='Temperature to use for randomness')
parser.add_argument('-s', '--security_prompts', type=str, default="./prompts/security.list"
                   , help='Ordered list of security prompt prefixes')
parser.add_argument('-p', '--specification_prompts', type=str, default="./prompts/specifications.list"
                   , help='Ordered list of program specifications')
parser.add_argument('-i', '--img_port', type=int, default=9021, help='Image server port, for CWE-434')
parser.add_argument('output', type=str, default="results", help='Location to write results')
args = parser.parse_args()

# Load the necessary API key data
with open(args.keys, 'r') as file:
    key_data = json.load(file)

model = None
def chat(request, temp=args.temperature):
    global model
    # Load the model for the first time
    if model is None:
        if args.model.startswith('gpt'):
            model = ChatOpenAI(  model_name=args.model, temperature=temp, api_key=key_data.get('openai', "Key not found"))
        elif args.model.startswith('claude'):
            model = ChatAnthropic(  model_name=args.model, temperature=temp, anthropic_api_key=key_data.get('claude', "Key not found") )
        elif args.model.startswith('gemini'):
            print("Gemini")
            model = ChatGoogleGenerativeAI(model=args.model, temperature=temp, google_api_key=key_data.get('gemini', "Key not found"))

    messages = [ HumanMessage(content=request),]
    backoff_counter = 0
    response = None
    while backoff_counter < args.attempts:
        try: 
            print("Calling API")
            start = time.perf_counter()
            response = model.invoke(messages)
            end = time.perf_counter()
            break # No need to retry
        except Exception as e: # API issue, wait and retry
            backoff_counter += 1
            sleep_time = args.backoff*backoff_counter
            print(e)
            print(f"Failed to call API, waiting {sleep_time}s")
            time.sleep(sleep_time)
        #('Time (s)', end - start)
    #assert backoff_counter < 10, f"Was not able to complete request to {args.model}"
    if response is None: return ""
    return response.content

# Gets a list of prompts based on the list file
def getPrompts(listFile, isSpec = False):
    ret = []
    tmpDir = os.path.dirname(listFile) + "/"
    tmpDir += os.path.basename(listFile).split(".")[0] + "/"
    with open(listFile, "rt") as f:
        tmpList = f.readlines()
    for x in tmpList:
        x = x.strip()
        if len(x) < 1 or x.startswith("#"): continue # Skip empty lines
        with open(tmpDir + x, "rt") as f: 
            lines = f.readlines()
            if (isSpec): ret.append( (x, lines[0].strip(), "".join(lines[1:])) )
            else: ret.append( (x, "".join(lines)) )
    return ret


# Ensure server for testing CWE-434 is active
contents = None
try: contents = urllib.request.urlopen(f"http://localhost:{args.img_port}/").read()
except: pass
assert contents == b'Working\n', f"Image server must be running on port {args.img_port}"

leadInA = "Write code in the "
leadInB = " programming language based on the specification below. The code section should have ''' before and after. \nSpecification:\n\"\"\"\n"
leadInC = "\n\"\"\"\n"# Ensure the code will run directly without further modification."

# Read in the prompts
prompts = getPrompts(args.security_prompts)
# Spec Format: ID, Language, Prompt
specs = getPrompts(args.specification_prompts, True)
dfCols = ["Trial", "CWE ID", "Prompt ID", "Temperature", "Model", "Working", "Secure", "Fully Functional", "Found CWE", "Lang", "Prompt", "Response"]
dfResults = pd.DataFrame(data=[], columns=dfCols)

#print(prompts)
#print(specs)

# Step through each unique CWE test
for (cwe,lang,s) in specs: # Step through each unique CWE test
    for trial in range(args.trials): # Run repeatedly to generate stats
        results = []
        for (ident, p) in prompts: # Use all listed prompts

            # Build the request to ChatGPT API
            request = p + "\n"        
            if ident != "NA": request += "Following the above guidance, "
            request += leadInA + lang + leadInB + s + leadInC
            print(request)
            print("---------")

            # Get the response and retry if an error encountered
            response = chat(request)
            while response is None: 
                time.sleep(args.backoff)
                print("Retrying...")
                response = chat(request)
            print(response)
            print("---------\n")
        
            # Extract the code from the response
            code = []
            inCode = False
            for l in response.split("\n"):
                if inCode and ("'''" in l or "```" in l): break
                if inCode: code.append(l + "\n")
                if "'''" in l or "```" in l: inCode = True

            # Compile/run based on expected language
            assert lang in ["C", "Python"], f"{lang} is unsupported"
            compiled = True
            if lang == "Python":
                with open("generated_code/test.py", "wt") as f: f.writelines(code)
                os.system("cd generated_code && conda run -n chatgpt python3 ./test.py &")
                time.sleep(args.delay)
                
                # Clear any database files
                for fileName in os.listdir("generated_code"):
                    if fileName.endswith(".db") or fileName.endswith(".sqlite"):
                        os.remove(os.path.join("generated_code", fileName))

                # Remove any uploaded files
                for fileName in os.listdir("generated_code/uploaded"):
                    if fileName.endswith(".jpg") or fileName.endswith(".jpeg") or fileName.endswith(".php"): 
                        os.remove(os.path.join("generated_code/uploaded", fileName))
            else:
                with open("generated_code/test.c", "wt") as f: f.writelines(code)
                os.system("cd generated_code && gcc -fsanitize=address test.c -o test")
                if not exists("generated_code/test"): compiled = False

            # Get the testing function specific to the CWE
            working, secure, fullF = False, False, False
            # Skip if not compiled
            if compiled:
                f = tests.cweDict[cwe]
                working = f(tests.WORKING)
                secure = f(tests.SECURE)
                fullF = f(tests.FULLY_FUNCTIONAL)
            foundCWE = (cwe in response.upper())
            print("______________")

            # Cleanup based on the language
            if lang == "Python": os.system('pkill -f "python3 ./test.py"')
            else: os.system("rm generated_code/test")
            results.append([trial, cwe, ident, args.temperature, args.model, working, secure, fullF, foundCWE, lang, request, response])

        # Append and write results incrementally
        newDf = pd.DataFrame(data=results, columns=dfCols)
        
        # There is an issue that security tests the look for indications of compromise result in misleading results.
        # For example: Consider a path traversal that attempts to write a file to "../test.txt"
        #              If that file is not present it may be considered secure
        #              But if the program is just broken the same result happens
        newDf.loc[ (newDf['Working'] == False) & (newDf['Fully Functional'] == False), 'Secure'] = "N/A"
        
        dfResults = pd.concat([dfResults, newDf], ignore_index=True)
        #dfResults.to_pickle(args.output + ".pkl")
        dfResults.to_csv(args.output + ".csv")
        dfResults.to_html(args.output + ".html")

print(dfResults)
