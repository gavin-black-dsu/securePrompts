#!/bin/env python

import pandas as pd
import os
import openai
import time
import tests
import argparse
from os.path import exists

parser = argparse.ArgumentParser(description='Send prompts to ChatGPT and analyze the resulting code')
parser.add_argument('-k', '--key', type=str, default=".key", help='File containing OpenAI API secret key')
parser.add_argument('-m', '--model', type=str, default="gpt-3.5-turbo", help='ChatGPT model to use')
parser.add_argument('-x', '--max_tokens', type=int, default=1024, help='Maximum number of tokens from ChatGPT')
parser.add_argument('-b', '--backoff', type=int, default=25, help='Seconds to wait until retrying ChatGPT request')
parser.add_argument('-d', '--delay', type=int, default=2, help='Seconds to wait for Flask server to start')
parser.add_argument('-n', '--trials', type=int, default=10, help='Number of times to repeat testing')
parser.add_argument('-t', '--temperature', type=float, default=1.0, help='Temperature to use for randomness')
parser.add_argument('-s', '--security_prompts', type=str, default="./prompts/security.list"
                   , help='Ordered list of security prompt prefixes')
parser.add_argument('-p', '--specification_prompts', type=str, default="./prompts/specifications.list"
                   , help='Ordered list of program specifications')
parser.add_argument('output', type=str, default="results", help='Location to write results')
args = parser.parse_args()

with open(args.key, "rt") as f: openai.api_key = f.readline()[:-1]

def chat(request, temp=args.temperature):
    message_history = []
    message_history.append({"role": "user", "content": request})

    try:
        completion = openai.ChatCompletion.create(
            model=args.model,
            messages=message_history,
            max_tokens=args.max_tokens,
            n=1,
            stop=None,
            temperature=temp,
        )
        reply = completion.choices[0].message.content
        return reply

    except openai.error.OpenAIError as error:
        print("OpenAI API error:", error)
        return None

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

leadInA = "Write code in the "
leadInB = " programming language based on the specification below. The code section should have ''' before and after. \nSpecification:\n\"\"\"\n"
leadInC = "\n\"\"\"\n"

# Read in the prompts
prompts = getPrompts(args.security_prompts)
# Spec Format: ID, Language, Prompt
specs = getPrompts(args.specification_prompts, True)
dfCols = ["Trial", "CWE ID", "Prompt ID", "Temperature", "Model", "Working", "Secure", "Fully Functional", "Found CWE", "Lang", "Prompt", "Response"]
dfResults = pd.DataFrame(data=[], columns=dfCols)

print(prompts)
print(specs)

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
                    if fileName.endswith(".db"): os.remove(os.path.join("generated_code", fileName))
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
        dfResults = pd.concat([dfResults, newDf], ignore_index=True)
        #dfResults.to_pickle(args.output + ".pkl")
        dfResults.to_csv(args.output + ".csv")

print(dfResults)

