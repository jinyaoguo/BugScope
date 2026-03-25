import streamlit as st
import sys
from pathlib import Path
import json
from datetime import datetime
import traceback
# Add the parent directory to the system path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from ui.logger import Logger
from llmtool.prompt_synthesizer import *
from llmtool.prompt_optimizer import *
from llmtool.bugscan.slice_bug_detector import *
from llmtool.extractor_synthesizer import *

# Language dictionary
language_dict = {
    "Cpp": "cpp",
    "Python": "python",
    "Java": "java",
    "Go": "go"
}

# Base path for results
BASE_PATH = Path(__file__).resolve().parents[3]

logger = Logger(f"{BASE_PATH}/log/webUI/{time.strftime('%Y-%m-%d', time.localtime())}.log")

def synthesize_page():
    st.title("Detection Prompt Synthesis")
    st.markdown("""
    This page allows you to create, view, and manage detection examples.
    You can synthesize your detection prompts with these examples.
    """)
    
    # Create tabs for adding new examples and viewing existing ones
    tab1, tab2, tab3, tab4 = st.tabs(["Add New Example", "View Existing Examples", "Generate Detection Prompt", "Generate Seed Extractor"])
    
    with tab1:
        st.subheader("Add a New Bug Detection Example")
        
        # Language Selection
        language = st.selectbox("Language", 
            options=["Cpp", "Python", "Java", "Go"],
            key=language_dict.keys())

        # Bug Type Input
        bug_type = st.text_input("Bug Type", 
                                 help="Enter the type of bug (e.g., NPD, BOF, UAF, ML)")
        
        # Pattern Description
        st.subheader("Pattern Description")
        pattern_desc = st.text_area("Describe the bug pattern", 
                                   help="Provide a detailed description of this bug pattern")
        
        # Initialize examples list in session state if it doesn't exist
        if 'code_examples' not in st.session_state:
            st.session_state.code_examples = [{
                "id": 0,
                "label": "Positive",
                "code": "",
                "description": ""
            }]
        
        # Display all examples
        st.subheader("Code Examples")
        examples_to_remove = []
        
        for i, example in enumerate(st.session_state.code_examples):
            with st.expander(f"Example {i+1}", expanded=True):
                col1, col2, col3 = st.columns([0.2, 0.7, 0.1])
                with col1:
                    label = st.radio("Example Type", 
                                   options=["Positive", "Negative"],
                                   key=f"label_{example['id']}",
                                   help="Positive = with bug, Negative = without bug")
                    example["label"] = label
                
                with col3:
                    if len(st.session_state.code_examples) > 1:
                        if st.button("Remove", key=f"remove_{example['id']}"):
                            examples_to_remove.append(example['id'])
                
                st.markdown(f"**{example['label']} Example**")
                code = st.text_area("Code", 
                                  value=example.get("code", ""),
                                  height=150,
                                  key=f"code_{example['id']}")
                example["code"] = code
                
                description = st.text_area("Description", 
                                         value=example.get("description", ""),
                                         height=100,
                                         key=f"desc_{example['id']}",
                                         help="Explain this example (e.g., why it has a bug or why it's fixed)")
                example["description"] = description
        
        # Remove examples marked for deletion
        if examples_to_remove:
            st.session_state.code_examples = [ex for ex in st.session_state.code_examples 
                                             if ex['id'] not in examples_to_remove]
        
        # Add new example button
        if st.button("Add Another Example"):
            # Find the highest ID and increment by 1
            max_id = max([ex["id"] for ex in st.session_state.code_examples]) + 1 if st.session_state.code_examples else 0
            st.session_state.code_examples.append({
                "id": max_id,
                "label": "Positive",
                "code": "",
                "description": ""
            })
            st.rerun()
        
        # Submit button
        if st.button("Submit Examples", use_container_width=True):
            if not bug_type:
                st.error("Please fill in all required fields (Bug Type and Pattern Description)")
            elif not any(ex["code"] for ex in st.session_state.code_examples):
                st.error("Please provide at least one code example")
            else:
                # Create data structure
                examples_data = []
                for example in st.session_state.code_examples:
                    if example["code"]:  # Only include examples with code
                        examples_data.append({
                            "label": example["label"],
                            "code": example["code"],
                            "description": example["description"]
                        })
                
                example_obj = {
                    "bug_type": bug_type,
                    "pattern_description": pattern_desc,
                    "examples": examples_data,
                    "created_at": str(datetime.now())
                }
                
                # Save the example
                examples_path = Path(f"{BASE_PATH}/src/prompt/{language}/Synthesis/dataset")
                examples_path.mkdir(exist_ok=True)
                
                # Create a unique filename
                file_path = examples_path / f"{bug_type}_{time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())}.json"
                
                with open(file_path, "w") as f:
                    json.dump(example_obj, f, indent=4)
                
                st.success(f"Examples saved successfully to {file_path.name}")
                # Clear the form
                st.session_state.code_examples = [{
                    "id": 0,
                    "label": "Positive",
                    "code": "",
                    "description": ""
                }]
    
    with tab2:
        st.subheader("Browse Existing Examples")
        
        # Find all example files
        examples_path = Path(f"{BASE_PATH}/src/prompt/{language}/Synthesis/dataset")
        if not examples_path.exists():
            st.info("No examples found. Add new examples using the form.")
        else:
            example_files = list(examples_path.glob("*.json"))
            if not example_files:
                st.info("No examples found. Add new examples using the form.")
            else:
                # Group examples by bug type
                bug_types = {}
                for file in example_files:
                    with open(file, "r") as f:
                        try:
                            data = json.load(f)
                            bug_type = data.get("bug_type", "Unknown")
                            if bug_type not in bug_types:
                                bug_types[bug_type] = []
                            bug_types[bug_type].append((file.name, data))
                        except:
                            pass
                
                # Select bug type to view
                selected_bug_type = st.selectbox("Filter by Bug Type", 
                                            options=["All"] + list(bug_types.keys()))
                
                if selected_bug_type == "All":
                    display_examples = [(name, data) for bt in bug_types.values() for name, data in bt]
                else:
                    display_examples = bug_types.get(selected_bug_type, [])
                
                # Initialize session state for editing
                if 'editing_example' not in st.session_state:
                    st.session_state.editing_example = {}
                
                # Display examples
                for name, example in display_examples:
                    example_key = f"{name}"
                    is_editing = st.session_state.editing_example.get(example_key, False)
                    
                    with st.expander(f"{example.get('bug_type')}: {name}", expanded=is_editing):
                        if is_editing:
                            # Edit Mode
                            st.subheader("Edit Bug Pattern")
                            
                            # Edit pattern description
                            edited_pattern_desc = st.text_area(
                                "Pattern Description", 
                                value=example.get("pattern_description", ""),
                                key=f"edit_desc_{example_key}"
                            )
                            
                            # Initialize edited examples in session state if not present
                            if f"edited_examples_{example_key}" not in st.session_state:
                                st.session_state[f"edited_examples_{example_key}"] = []
                                for ex in example.get("examples", []):
                                    st.session_state[f"edited_examples_{example_key}"].append(ex.copy())
                            
                            # Display editable examples
                            st.subheader("Edit Examples")
                            examples_to_remove = []
                            
                            for i, ex in enumerate(st.session_state[f"edited_examples_{example_key}"]):
                                with st.container():
                                    col1, col2 = st.columns([4, 1])
                                    with col1:
                                        st.markdown(f"### Example {i+1}")
                                    with col2:
                                        if len(st.session_state[f"edited_examples_{example_key}"]) > 1:
                                            if st.button("Remove", key=f"remove_ex_{example_key}_{i}"):
                                                examples_to_remove.append(i)
                                    
                                    # Edit example type (Positive/Negative)
                                    label = st.radio(
                                        "Example Type", 
                                        options=["Positive", "Negative"],
                                        index=0 if ex.get("label") == "Positive" else 1,
                                        key=f"edit_label_{example_key}_{i}",
                                        horizontal=True
                                    )
                                    ex["label"] = label
                                    
                                    # Edit code
                                    code = st.text_area(
                                        "Code",
                                        value=ex.get("code", ""),
                                        height=150,
                                        key=f"edit_code_{example_key}_{i}"
                                    )
                                    ex["code"] = code
                                    
                                    # Edit description
                                    description = st.text_area(
                                        "Description",
                                        value=ex.get("description", ""),
                                        height=100,
                                        key=f"edit_desc_ex_{example_key}_{i}"
                                    )
                                    ex["description"] = description
                                    st.markdown("---")
                            
                            # Remove examples marked for deletion
                            if examples_to_remove:
                                for idx in sorted(examples_to_remove, reverse=True):
                                    st.session_state[f"edited_examples_{example_key}"].pop(idx)
                                st.rerun()
                            
                            # Add new example button
                            if st.button("Add Example", key=f"add_example_{example_key}"):
                                st.session_state[f"edited_examples_{example_key}"].append({
                                    "label": "Positive",
                                    "code": "",
                                    "description": ""
                                })
                                st.rerun()
                            
                            # Save/Cancel buttons
                            col1, col2 = st.columns(2)
                            with col1:
                                if st.button("Save Changes", key=f"save_{example_key}", use_container_width=True):
                                    # Create updated data structure
                                    updated_example = example.copy()
                                    updated_example["pattern_description"] = edited_pattern_desc
                                    updated_example["examples"] = st.session_state[f"edited_examples_{example_key}"]
                                    updated_example["updated_at"] = str(datetime.now())
                                    
                                    # Save back to file
                                    file_path = examples_path / name
                                    with open(file_path, "w") as f:
                                        json.dump(updated_example, f, indent=4)
                                    
                                    # Exit edit mode
                                    st.session_state.editing_example[example_key] = False
                                    st.success(f"Changes saved successfully!")
                                    # Clear session state for this example
                                    if f"edited_examples_{example_key}" in st.session_state:
                                        del st.session_state[f"edited_examples_{example_key}"]
                                    st.rerun()
                            
                            with col2:
                                if st.button("Cancel", key=f"cancel_{example_key}", use_container_width=True):
                                    # Exit edit mode without saving
                                    st.session_state.editing_example[example_key] = False
                                    # Clear session state for this example
                                    if f"edited_examples_{example_key}" in st.session_state:
                                        del st.session_state[f"edited_examples_{example_key}"]
                                    st.rerun()
                        
                        else:
                            # View Mode
                            st.markdown(f"**Pattern Description:**")
                            st.markdown(example.get("pattern_description", "No description provided"))
                            
                            if "examples" in example:  # New format with multiple examples
                                for i, ex in enumerate(example["examples"]):
                                    label_color = "green" if ex.get("label") == "Negative" else "red"
                                    st.markdown(f"### Example {i+1} - <span style='color:{label_color}'>{ex.get('label')}</span>", unsafe_allow_html=True)
                                    
                                    if ex.get("description"):
                                        st.markdown(f"**Description:** {ex.get('description')}")
                                    
                                    st.code(ex.get("code", ""), 
                                        language=language_dict.get(ex.get("language", "Cpp"), "cpp").lower())
                            
                            st.markdown(f"**Create Time:** {example.get('created_at', 'Unknown')}")
                            if example.get('updated_at'):
                                st.markdown(f"**Last Updated:** {example.get('updated_at')}")
                            
                            # Add Edit and Delete buttons
                            col1, col2 = st.columns(2)
                            with col1:
                                if st.button("Edit Example", key=f"edit_{example_key}", use_container_width=True):
                                    st.session_state.editing_example[example_key] = True
                                    st.rerun()
                            
                            with col2:
                                if st.button("Delete Example", key=f"delete_{example_key}", use_container_width=True):
                                    try:
                                        (examples_path / name).unlink()
                                        st.success(f"Example {name} deleted successfully!")
                                        st.rerun()
                                    except Exception as e:
                                        st.error(f"Failed to delete example: {str(e)}")
        
    with tab3:
        st.subheader("Generate Detection Prompt")
        
        # Language Selection
        language = st.selectbox("Language", 
            options=["Cpp", "Python", "Java", "Go"],
            key="gen_language")
        
        # Model Selection
        model = st.selectbox(
            "Select Model",
            options=["claude-3.5", "claude-3.7", "o4-mini", "gpt-4o", "gpt-4-turbo", "gpt-4o-mini", "deepseek-local", "deepseek-chat", "deepseek-reasoner", "gemini"],
            help="Select the model"
        )

        # Find all available example files
        examples_path = Path(f"{BASE_PATH}/src/prompt/{language}/Synthesis/dataset")
        if not examples_path.exists() or not list(examples_path.glob("*.json")):
            st.info(f"No examples found for {language}. Please add examples first.")
        else:
            example_files = []
            example_file_info = {}
            
            # Get all example files
            for file in examples_path.glob("*.json"):
                try:
                    with open(file, "r") as f:
                        data = json.load(f)
                        bug_type = data.get("bug_type", "Unknown")
                        file_name = file.name
                        display_name = f"{bug_type} ({file_name})"
                        example_files.append(display_name)
                        example_file_info[display_name] = {
                            "path": file,
                            "data": data
                        }
                except Exception as e:
                    pass
            
            if not example_files:
                st.warning("No valid examples found. Please add examples with valid file formats.")
            else:
                # Example File Selection
                selected_example = st.selectbox(
                    "Select Example File",
                    options=example_files,
                    help="Choose an example file to generate detection prompt"
                )
                
                # Display example information
                if selected_example in example_file_info:
                    example_data = example_file_info[selected_example]["data"]
                    example_path = example_file_info[selected_example]["path"]
                    selected_bug_type = example_data.get("bug_type", "Unknown")
                    
                    try:
                        # Show pattern description
                        st.markdown("### Bug Pattern Description")
                        st.info(example_data.get("pattern_description", "No description available"))
                        
                        # Show example count
                        example_count = len(example_data.get("examples", []))
                        st.markdown(f"**Available Examples:** {example_count} ({sum(1 for ex in example_data.get('examples', []) if ex.get('label') == 'Positive')} positive, {sum(1 for ex in example_data.get('examples', []) if ex.get('label') == 'Negative')} negative)")
                        
                        # Generate button
                        if st.button("Generate Detection Prompt", type="primary", use_container_width=True):
                            with st.spinner("Generating prompt... This may take a moment."):
                                try:
                                    # Pass the example file name without extension instead of just bug_type
                                    example_name = example_path.stem  # Get filename without extension
                                    st.session_state.synthesize_prompt, elapsed_time, input_token_cost, output_token_cost = synthesize_prompt(model, language, selected_bug_type, example_name)
                                    if st.session_state.synthesize_prompt:
                                        st.success("Detection prompt generated successfully!")
                                except Exception as e:
                                    st.error(f"Failed to generate prompt: {str(e)}")
                                    st.error("Please check if the example data is properly formatted.")
                        
                        if st.session_state.synthesize_prompt != "":
                            # Display the generated prompt
                            st.markdown("### Generated Detection Prompt")
                            st.code(st.session_state.synthesize_prompt, language="json")

                            st.markdown("### Token Usage")
                            st.write(f"**Elapsed Time:** {elapsed_time:.2f} seconds")
                            st.write(f"**Input Token Cost:** {input_token_cost} tokens")
                            st.write(f"**Output Token Cost:** {output_token_cost} tokens")

                            # Download button
                            st.download_button(
                                "Download Prompt",
                                data=st.session_state.synthesize_prompt,
                                file_name=f"{selected_bug_type}_detection_prompt.json",
                                mime="application/json",
                                use_container_width=True
                            )
                            
                            # Save to file option
                            if st.checkbox("Save to Prompt Library"):
                                prompt_library_path = Path(f"{BASE_PATH}/src/prompt/{language}/Synthesis/library")
                                print(prompt_library_path)
                                prompt_library_path.mkdir(exist_ok=True, parents=True)
                                print(prompt_library_path)
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                prompt_file = prompt_library_path / f"{selected_bug_type}_{timestamp}.json"
                                
                                st.info(f"File will be saved to: {prompt_file.absolute()}")
                                
                                try:
                                    with open(prompt_file, "w") as f:
                                        f.write(st.session_state.synthesize_prompt)
                                    st.success(f"Prompt successfully saved to: {prompt_file.absolute()}")
                                    print(f"Prompt successfully saved to: {prompt_file.absolute()}")
                                except Exception as e:
                                    st.error(f"Error saving file: {str(e)}")
                                    print(f"Error saving file: {str(e)}")
                    except Exception as e:
                        st.error(f"Error processing example data: {str(e)}")

    with tab4:
        st.subheader("Generate Seed Extractor")
        
        # Language Selection
        language = st.selectbox("Language", 
            options=["Cpp", "Python", "Java", "Go"],
            key="extractor_language")
        
        # Model Selection
        model = st.selectbox(
            "Select Model",
            options=["claude-3.5", "claude-3.7", "o4-mini", "gpt-4o", "gpt-4-turbo", "gpt-4o-mini", "deepseek-local", "deepseek-chat", "deepseek-reasoner", "gemini"],
            key="extractor_model",
            help="Select the model"
        )

        # Find all available example files
        examples_path = Path(f"{BASE_PATH}/src/prompt/{language}/Synthesis/dataset")
        if not examples_path.exists() or not list(examples_path.glob("*.json")):
            st.info(f"No examples found for {language}. Please add examples first.")
        else:
            example_files = []
            example_file_info = {}
            
            # Get all example files
            for file in examples_path.glob("*.json"):
                try:
                    with open(file, "r") as f:
                        data = json.load(f)
                        bug_type = data.get("bug_type", "Unknown")
                        file_name = file.name
                        display_name = f"{bug_type} ({file_name})"
                        example_files.append(display_name)
                        example_file_info[display_name] = {
                            "path": file,
                            "data": data
                        }
                except Exception as e:
                    pass
            
            if not example_files:
                st.warning("No valid examples found. Please add examples with valid file formats.")
            else:
                # Example File Selection
                selected_example = st.selectbox(
                    "Select Example File",
                    options=example_files,
                    key="extractor_example",
                    help="Choose an example file to generate seed extractor"
                )
                
                # Display example information
                if selected_example in example_file_info:
                    example_data = example_file_info[selected_example]["data"]
                    example_path = example_file_info[selected_example]["path"]
                    selected_bug_type = example_data.get("bug_type", "Unknown")
                    
                    try:
                        # Show pattern description
                        st.markdown("### Bug Pattern Description")
                        st.info(example_data.get("pattern_description", "No description available"))
                        
                        # Show example count
                        example_count = len(example_data.get("examples", []))
                        st.markdown(f"**Available Examples:** {example_count} ({sum(1 for ex in example_data.get('examples', []) if ex.get('label') == 'Positive')} positive, {sum(1 for ex in example_data.get('examples', []) if ex.get('label') == 'Negative')} negative)")
                        
                        # Generate button
                        if st.button("Generate Seed Extractor", type="primary", key="generate_extractor_btn", use_container_width=True):
                            with st.spinner("Generating extractor... This may take a moment."):
                                try:
                                    # Pass the example file name without extension instead of just bug_type
                                    example_name = example_path.stem  # Get filename without extension
                                    st.session_state.synthesized_extractor, elapsed_time, input_token_cost, output_token_cost = synthesize_extractor(model, language, selected_bug_type, example_name)
                                    if st.session_state.synthesized_extractor:
                                        st.success("Seed extractor generated successfully!")
                                except Exception as e:
                                    st.error(f"Failed to generate extractor: {str(e)}")
                                    st.error("Please check if the example data is properly formatted.")
                        
                        # Initialize the session state variable if it doesn't exist
                        if "synthesized_extractor" not in st.session_state:
                            st.session_state.synthesized_extractor = ""
                        
                        if st.session_state.synthesized_extractor:
                            # Display the generated extractor
                            st.markdown("### Generated Seed Extractor")
                            st.code(st.session_state.synthesized_extractor, language="python")

                            # Show elapsed time and token costs
                            st.markdown("### Performance Metrics")
                            st.markdown(f"**Elapsed Time:** {elapsed_time:.2f} seconds")
                            st.markdown(f"**Input Token Cost:** {input_token_cost} tokens")
                            st.markdown(f"**Output Token Cost:** {output_token_cost} tokens")

                            # Download button
                            st.download_button(
                                "Download Extractor",
                                data=st.session_state.synthesized_extractor,
                                file_name=f"{selected_bug_type}_seed_extractor.py",
                                mime="text/plain",
                                key="download_extractor_btn",
                                use_container_width=True
                            )
                            
                            # Save to file option
                            if st.checkbox("Save to Extractor Library", key="save_extractor_checkbox"):
                                extractor_library_path = Path(f"{BASE_PATH}/src/tstool/bugscan_extractor/synthesis")
                                extractor_library_path.mkdir(exist_ok=True, parents=True)
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                extractor_file = extractor_library_path / f"{language}_{selected_bug_type}_{timestamp}.py"
                                
                                st.info(f"File will be saved to: {extractor_file.absolute()}")
                                
                                try:
                                    with open(extractor_file, "w") as f:
                                        f.write(st.session_state.synthesized_extractor)
                                    st.success(f"Extractor successfully saved to: {extractor_file.absolute()}")
                                except Exception as e:
                                    st.error(f"Error saving file: {str(e)}")
                    except Exception as e:
                        st.error(f"Error processing example data: {str(e)}")


# def synthesize_prompt(model, language, bug_type, example_name) -> str:
#     input = PromptSynthesizerInput(language, example_name) 
#     synthesizer = PromptSynthesizer(
#         model_name=model,
#         temperature=0,
#         language=language,
#         bug_type=bug_type,
#         max_query_num=5,
#         logger=logger
#     )
    
#     try:
#         output: PromptSynthesizerOutput = synthesizer.invoke(input)
#         if output and hasattr(output, 'is_valid_json') and output.is_valid_json:
#             return output.generated_prompt
#         else:
#             st.error("Generated prompt is not valid JSON.")
#             if output:
#                 return output.generated_prompt  
#             return None
#     except Exception as e:
#         st.error(f"Error during prompt synthesis: {str(e)}")
#         st.error(traceback.format_exc())
#         return None
    
### Measure the time and token cost of prompt synthesis
def synthesize_prompt(model, language, bug_type, example_name) -> Tuple[str, float, int, int]:
    """
    Synthesize a detection prompt based on the provided model, language, bug type, and example name.
    Output:
        - generated_prompt: The synthesized detection prompt as a string.
        - elapsed_time: Time taken to synthesize the prompt in seconds.
        - input_token_cost: Number of input tokens used.
        - output_token_cost: Number of output tokens generated.
    """
    start_time = time.time()
    input = PromptSynthesizerInput(language, example_name) 
    synthesizer = PromptSynthesizer(
        model_name=model,
        temperature=0,
        language=language,
        bug_type=bug_type,
        max_query_num=5,
        logger=logger
    )
    
    try:
        output: PromptSynthesizerOutput = synthesizer.invoke(input)
        end_time = time.time()
        elapsed_time = end_time - start_time
        if output and hasattr(output, 'is_valid_json') and output.is_valid_json:
            return output.generated_prompt, elapsed_time, synthesizer.input_token_cost, synthesizer.output_token_cost
        else:
            st.error("Generated prompt is not valid JSON.")
            if output:
                return output.generated_prompt, elapsed_time, synthesizer.input_token_cost, synthesizer.output_token_cost
            return None
    except Exception as e:
        st.error(f"Error during prompt synthesis: {str(e)}")
        st.error(traceback.format_exc())
        return None

    
def synthesize_extractor(model, language, bug_type, example_name) -> Tuple[str, float, int, int]:
    start_time = time.time()
    input = ExtractorSynthesizerInput(language, example_name)
    synthesizer = ExtractorSynthesizer(
        model_name=model,
        temperature=0,
        language=language,
        bug_type=bug_type,
        max_query_num=5,
        logger=logger
    )
    
    try:
        output: ExtractorSynthesizerOutput = synthesizer.invoke(input)
        end_time = time.time()
        elapsed_time = end_time - start_time
        return output.generated_extractor, elapsed_time, synthesizer.input_token_cost, synthesizer.output_token_cost
    except Exception as e:
        st.error(f"Error during extractor synthesis: {str(e)}")
        st.error(traceback.format_exc())
        return None
    
if __name__ == "__main__":
    st.set_page_config(
        layout="wide",  # Use wide layout instead of centered
        initial_sidebar_state="expanded"
    )
    if "synthesize_prompt" not in st.session_state:
        st.session_state.synthesize_prompt = ""
    synthesize_page()