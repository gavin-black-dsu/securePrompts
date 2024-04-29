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
parser.add_argument('-k', '--keys', type=str, default="keys.json", help='File containing OpenAI API secret key')
parser.add_argument('-m', '--model', type=str, default="gpt-3.5-turbo", help='ChatGPT model to use')
parser.add_argument('-x', '--max_tokens', type=int, default=2048, help='Maximum number of tokens from ChatGPT')
parser.add_argument('-b', '--backoff', type=int, default=25, help='Seconds to wait until retrying ChatGPT request')
parser.add_argument('-n', '--trials', type=int, default=30, help='Number of times to repeat testing')
parser.add_argument('-t', '--temperature', type=float, default=0.0, help='Temperature to use for randomness')
parser.add_argument('-c', '--chain', type=bool, default=False, help='Use chain prompts')
parser.add_argument('-l', '--label', type=str, default="All", help='Label for later graphs')
parser.add_argument('-s', '--security_prompt', type=str, default="./prompts/security/All"
                   , help='Security prompt to test with')
parser.add_argument('-p', '--specification_prompt', type=str, default="./prompts/specifications/CWE-125"
                   , help='Ordered list of program specifications')
parser.add_argument('output', type=str, default="results", help='Location to write results')
args = parser.parse_args()


modelLookup = { "gpt-3.5-turbo": "GPT-3.5", 
                "gpt-4": "GPT-4", 
                "gemini-pro": "Gemini 1.0", 
                "claude-instant-1.2":  "Claude Instant", 
                "claude-3-opus-20240229": "Claude Opus"
              }

assert args.model in modelLookup.keys(), f"Model not in dictionary: {modelLookup}"
modelName = modelLookup[args.model]
print(modelName)

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
    messages = [ HumanMessage(content=str(request)),]
    response = None
    
    print("Calling API")
    start = time.perf_counter()
    response = model.invoke(messages)
    end = time.perf_counter()
    t = end - start
    print(f"Time: {t}")
    
    if response is None: return ""
    return (response.content, t)


def chat_fail(message_history, temp=args.temperature):
    try:
        t0 = time.time()
        completion = openai.ChatCompletion.create(
            model=args.model,
            messages=message_history,
            max_tokens=args.max_tokens,
            n=1,
            stop=None,
            temperature=temp,
        )
        t1 = time.time()
        t = t1-t0
        reply = completion.choices[0].message.content
        return (reply, t)

    except openai.error.OpenAIError as error:
        print("OpenAI API error:", error)
        return (None, 0)

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


def chatWrapper(message_history):
    # Get the response and retry if an error encountered
    (response, t) = chat(message_history)
    while response is None: 
        time.sleep(args.backoff)
        print("Retrying...")
        (response, t) = chat(message_history)
    return (response, t)


leadInA = "Write code in the "
leadInB = " programming language based on the specification below. The code section should have ''' before and after. \nSpecification:\n\"\"\"\n"
leadInC = "\n\"\"\"\n"

sec_prompt = ""
with open(args.security_prompt, "rt") as f: 
    lines = f.readlines()
    sec_prompt = "".join(lines)

spec = ""
with open(args.specification_prompt, "rt") as f: 
    lines = f.readlines()
    lang = lines[0].strip()
    spec = "".join(lines[1:])

results = []
request = sec_prompt + "\n"
if "None" not in args.security_prompt:
    request += "Following the above guidance, "
request += leadInA + lang + leadInB + spec + leadInC

for trial in range(args.trials): # Run repeatedly to generate stats
    print(f"{trial}/{args.trials}")
    message_history = []
    message_history.append({"role": "user", "content": request})
    totalTime = 0
    (response, t) = chatWrapper(message_history)
    totalTime += t
    if args.chain:
        message_history.append({"role": "user", "content": "Identify any potential CWEs in the code"})
        message_history.append({"role": "assistant", "content": response})
        (response, t) = chatWrapper(message_history)
        totalTime += t
        message_history.append({"role": "user", "content": "Update the code to be as secure as possible and avoid CWEs"})
        message_history.append({"role": "assistant", "content": response})
        (response, t) = chatWrapper(message_history)
        totalTime += t

    results.append((modelName,args.label,totalTime))
    print(results[-1])

dfResults = pd.DataFrame(results)
dfResults.to_csv(args.output + ".csv")
