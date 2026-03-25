from os import path
import json
from llmtool.LLM_utils import *
from llmtool.LLM_tool import *
from memory.syntactic.function import *
from memory.syntactic.value import *
from memory.syntactic.api import *
from tstool.bugscan_extractor.ast import *
BASE_PATH = Path(__file__).resolve().parent.parent.parent


class ExtractorSynthesizerInput(LLMToolInput):
    def __init__(self, language: str, example_file: str) -> None:
        """
        :param language: the programming language
        :param example_file: the name of the example file
        """
        self.example_path = f"{BASE_PATH}/src/prompt/{language}/Synthesis/dataset/{example_file}.json"
        return
    
    def __hash__(self) -> int:
        return hash(self.example_path)


class ExtractorSynthesizerOutput(LLMToolOutput):
    def __init__(self, generated_extractor: str) -> None:
        """
        :param generated_prompt: the generated prompt string
        """
        self.generated_extractor = generated_extractor
        return
    
    def __str__(self):
        return f"Synthesized detection prompt: {self.generated_extractor}"


class ExtractorSynthesizer(LLMTool):
    def __init__(self, model_name: str, temperature: float, language: str, bug_type: str, max_query_num: int, logger: Logger) -> None:
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self.bug_type = bug_type
        self.prompt_file = f"{BASE_PATH}/src/prompt/{language}/Synthesis/extractor_synthesizer.json"
        self.template_path = f"{BASE_PATH}/src/tstool/bugscan_extractor/{language}/template.py"
        return

    def _get_prompt(self, input: ExtractorSynthesizerInput) -> str:
        """
        :param input: the input of prompt synthesizer
        :return: the prompt string
        """
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)

        with open(input.example_path, "r") as f:
            example_info = json.load(f)
        
        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules"])
        prompt += "\n" + "\n".join(prompt_template_dict["meta_prompts"])
        prompt = prompt.replace("<ANSWER>", "\n".join(prompt_template_dict["answer_format"]))
        prompt = prompt.replace("<EXAMPLE>", "\n".join(prompt_template_dict["example"]))
        prompt = prompt.replace("<UTILITIES>", "\n".join(prompt_template_dict["utilities"]))
        prompt = prompt.replace("<BUG_TYPE>", example_info["bug_type"])

        positive_examples = [example for example in example_info["examples"] if example["label"] == "Positive"]

        positive_example_str = ""
        for i, example in enumerate(positive_examples):
            positive_example_str += f"Example {i + 1}:\n"
            positive_example_str += f"Code: {example['code']}\n"
            positive_example_str += f"Description: {example['description']}\n"
            positive_example_str += f"AST Tree: {get_AST(example['code'], self.language)}\n"
            positive_example_str += f"\n"
        prompt = prompt.replace("<POSITIVE_EXAMPLES>", positive_example_str)
        
        with open(self.template_path, "r") as f:
            template_str = f.read()
        prompt = prompt.replace("<TEMPLATE>", template_str)
        print(f"Prompt: {prompt}")
        return prompt

    def _parse_response(self, response: str, audit_request_formulator_input: ExtractorSynthesizerInput) -> ExtractorSynthesizerOutput:
        """
        Parse the response from the model.
        :param response: the response from the model
        :param audit_request_formulator_input: the audit_request_formulator_input of the tool
        :return: the output of the tool
        """
        pattern = re.compile(r"~~~(?:\w+)?\s*([\s\S]*?)\s*~~~")
        match = pattern.search(response)
        if match:
            output = ExtractorSynthesizerOutput(match.group(1))
        else:
            self.logger.print_log(f"Synthesized extractor not found in output")
            output = None
        print(response)
        return output
        