from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from langchain.chains import LLMChain
from langchain.llms import LlamaCpp
from langchain.prompts import PromptTemplate

#MODEL_PATH = "./llama-2-7b-chat.ggmlv3.guf.q8_0.bin"
#MODEL_PATH = "llama-2-7b.Q4_K_M.gguf"
MODEL_PATH = "llama-2-7b-ggmlv3.guf.q4_0.bin"
# Callbacks support token-wise streaming
callback_manager = CallbackManager([StreamingStdOutCallbackHandler()])

template = """Question: {question}

Answer: Let's work this out in a step by step way to be sure we have the right answer."""

prompt = PromptTemplate(template=template, input_variables=["question"])

# Make sure the model path is correct for your system!
n_gpu_layers = 1  # Metal set to 1 is enough.
n_batch = 512  # Should be between 1 and n_ctx, consider the amount of RAM of your Apple Silicon Chip.
llm = LlamaCpp(
    model_path=MODEL_PATH,
    #temperature=0.75,
    #max_tokens=2000,
    #top_p=1,
    n_gpu_layers=n_gpu_layers,
    n_batch=n_batch,
    f16_kv=True,
    callback_manager=callback_manager,
    verbose=True,  # Verbose is required to pass to the callback manager
    grammar_path="json.gbnf",
)

#prompt = """
#Question: A rap battle between Stephen Colbert and John Oliver
#"""
#llm(prompt)

#prompt = """
#Question: What is the capital of Italy?
#"""

#llm(prompt)

result = llm("Describe person in JSON format:") #with name, surname, e-mail