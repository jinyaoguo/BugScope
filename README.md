# BugScope

BugScope is a repo-level bug detector for general bugs. Currently, it supports the detection of diverse bug types (such as Null Pointer Dereference, Memory Leak, and Use After Free). It leverages tree-sitter to parse the codebase and uses LLM to mimic the process of manual code auditing. Compared with existing code auditing tools, BugScope offers the following advantages:

- Compilation-Free Analysis
- Multiple Bug Type Detection
- Customization Support

## Agents in BugScope

BugScope is a multi-agent framework for code auditing. We offer the following agent instances in our current version:

- **SliceScanAgent** in `slicescan.py`: An inter-procedural forward/backward slicing agent.

- **BugScanAgent** in `bugscan.py`: A general bug detector not restricted to data-flow bugs. Currently, it supports the detection of buffer overflow.

## Installation

1. Create and activate a conda environment with Python 3.9.18:

   ```sh
   conda create -n bugscope python=3.9.18
   conda activate bugscope
   ```

2. Install the required dependencies:

   ```sh
   cd BugScope
   pip install -r requirements.txt
   ```

3. Ensure you have the Tree-sitter library and language bindings installed:

   ```sh
   cd lib
   python build.py
   ```

4. Configure the OpenAI API key.

   ```sh
   export OPENAI_API_KEY=xxxxxx >> ~/.bashrc
   ```

   For Claude3.5, we use the model hosted by Amazon Bedrock. If you want to use Claude-3.5 and Claude-3.7, you may need to set up the environment first.


## Quick Start

1. We have prepared several benchmark programs in the `benchmark` directory for a quick start. Some of these are submodules, so you may need to initialize them using the following commands:

   ```sh
   cd BugScope
   git submodule update --init --recursive
   ```

2. We provide the script `src/run_bugscope.sh` to run different types of scans. You can use the following command to look up how to run `run_bugscope.sh`.

    ```sh
    cd src
    bash run_bugscope.sh --help
    ```

   Here are some example commands:

   ```sh
   # For general bug scanning (bugscan)
   bash run_bugscope.sh bugscan --language Cpp --project-path ../benchmark/Cpp/htop --is-iterative
   ```

3. After the scanning is complete, the results will be available in JSON format and log files.


## Web UI

BugScope provides a Streamlit Web UI for viewing scan results and developing
bug-detection configurations. Start it from the repository root after activating
the BugScope environment:

```sh
cd BugScope
conda activate bugscope
streamlit run src/ui/web_ui.py
```

By default, the UI is available at `http://localhost:8501`. When BugScope is
running on a remote server, start Streamlit with a listening address and port:

```sh
streamlit run src/ui/web_ui.py \
  --server.address 0.0.0.0 \
  --server.port 8501 \
  --server.headless true
```

You can then access `http://<server-address>:8501`, subject to the server's
network and firewall settings. Alternatively, forward the port over SSH and
open `http://localhost:8501` locally:

```sh
ssh -L 8501:localhost:8501 <user>@<server-address>
```

The Web UI contains three pages:

1. **Main page** visualizes detection results produced by BugScope. Open the
   **Results** view, select the language, scanner, model, bug type, project, and
   scan timestamp, and then inspect the detected bugs. You can display source
   functions, mark findings as true or false positives, save human labels, and
   download the displayed results. Run a scan first so that its output exists
   under the repository's `result` directory.

2. **Synthesizer** synthesizes a detection prompt and a retrieval strategy
   (shown in the UI as a **Seed Extractor**) from positive and negative code
   examples. First add or select an example dataset, then use **Generate
   Detection Prompt** or **Generate Seed Extractor**. The generated artifacts
   can be reviewed, downloaded, and optionally saved to the corresponding
   BugScope library. Prompt generation requires credentials for the selected
   model.

3. **Optimizer** improves an existing detection prompt using false-positive and
   false-negative feedback. Add or select feedback, run **Optimize Detection
   Prompt**, and use **Evaluate Detection Prompt** to evaluate the original or
   optimized prompt. The optimized prompt can also be downloaded for later use.


## Parallel Auditing Support

For a large repository, a sequential analysis process may be quite time-consuming. To accelerate the analysis, you can choose parallel auditing. Specifically, you can set the option `--max-neural-workers` to a larger value. By default, this option is set to 6 for parallel auditing.
Also, we have set the parsing-based analysis in a parallel mode by default. The default maximal number of workers is 10.

## License

This project is licensed under the **GNU General Public License v2.0 (GPLv2)**.  You are free to use, modify, and distribute the software under the terms of this license, provided that derivative works are also distributed under the same license.

For full details, see the [LICENSE](LICENSE) file or visit the official license page: [https://www.gnu.org/licenses/old-licenses/gpl-2.0.html](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
