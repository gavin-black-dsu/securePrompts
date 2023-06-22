# ChatGPT Security Focused Prompts and Code Correctness

## Setup

Install the requirements in **requirements.txt**, e.g. <code>pip3 install -r requirements.txt</code>

OpenAI Secret key must be in **.key** file, or the file passed in as an argument.

## Running

```
usage: ./prompts.py [-h] [-k KEY] [-m MODEL] [-x MAX_TOKENS] [-b BACKOFF] [-d DELAY] [-n TRIALS] [-t TEMPERATURE] output

Send prompts to ChatGPT and analyze the resulting code

positional arguments:
  output                Location to write results

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     File containing OpenAI API secret key
  -m MODEL, --model MODEL
                        ChatGPT model to use
  -x MAX_TOKENS, --max_tokens MAX_TOKENS
                        Maximum number of tokens from ChatGPT
  -b BACKOFF, --backoff BACKOFF
                        Seconds to wait until retrying ChatGPT request
  -d DELAY, --delay DELAY
                        Seconds to wait for Flask server to start
  -n TRIALS, --trials TRIALS
                        Number of times to repeat testing
  -t TEMPERATURE, --temperature TEMPERATURE
                        Temperature to use for randomness
```
## Adding Prompts

TBD

## Adding Tests

TBD
