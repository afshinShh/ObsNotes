- [Karpathy summarizes this well](https://x.com/karpathy/status/1937902205765607626?ref=blog.langchain.com):
> [!quote] Context engineering is the ”…delicate art and science of filling the context window with just the right information for the next step.”_

- Drew Breunig [nicely outlined](https://www.dbreunig.com/2025/06/22/how-contexts-fail-and-how-to-fix-them.html?ref=blog.langchain.com) a number of specific ways that longer context can cause perform problems
	- [Context Poisoning: When a hallucination makes it into the context](https://www.dbreunig.com/2025/06/22/how-contexts-fail-and-how-to-fix-them.html?ref=blog.langchain.com#context-poisoning)
	- [Context Distraction: When the context overwhelms the training](https://www.dbreunig.com/2025/06/22/how-contexts-fail-and-how-to-fix-them.html?ref=blog.langchain.com#context-distraction)
	- [Context Confusion: When superfluous context influences the response](https://www.dbreunig.com/2025/06/22/how-contexts-fail-and-how-to-fix-them.html?ref=blog.langchain.com#context-confusion)
	- [Context Clash: When parts of the context disagree](https://www.dbreunig.com/2025/06/22/how-contexts-fail-and-how-to-fix-them.html?ref=blog.langchain.com#context-clash)
# [The Four Strategies](https://newsletter.owainlewis.com/p/4-context-engineering-strategies)

1. **Write (External Memory)**
2. **Select (Just-in-Time Retrieval)**
3. **Compress and Prune**
4. **Isolate (Multi-Agent Systems)**

![[Pasted image 20260705114008.png]]
## External Memory (Write Context)

_Writing context means saving it outside the context window to help an agent perform a task._
External memory, in the context of large language models (LLMs), refers to mechanisms that allow these models to access and utilize information stored outside of their internal parameters. This can involve retrieving relevant data from databases, knowledge graphs, or other external sources during the prompt processing or generation phases to augment the model's knowledge and improve its performance on specific tasks. This enhances the LLM's ability to handle complex queries and generate more accurate and contextually relevant responses.

## RAG and Dynamic Filters (Select Context)

_Selecting context means pulling it into the context window to help an agent perform a task._
Retrieval-Augmented Generation (RAG) enhances Large Language Models (LLMs) by providing them with relevant, up-to-date information from external sources. Dynamic filters are techniques that selectively filter the information retrieved for RAG, ensuring that the LLM receives only the most pertinent context based on the specific query and user. This results in more accurate, focused, and contextually appropriate LLM responses.
## Context Compaction

_Compressing context involves retaining only the tokens required to perform a task._
Context compaction is a technique used to reduce the length of the context provided to a large language model (LLM) without sacrificing relevant information. This process aims to remove redundant, irrelevant, or less important information from the context window to make room for more data or improve the efficiency and effectiveness of the LLM's processing. Compaction can involve techniques like summarization, filtering, or re-ranking of context information.

## Context Isolation

_Isolating context involves splitting it up to help an agent perform a task._
Context isolation is about keeping different tasks or areas of knowledge separate when working with large language models (LLMs). Think of it like giving each task its own dedicated space. Instead of one big LLM trying to handle everything at once, you use multiple, smaller "agents" that are each focused on a specific job and trained on their own specific data. This prevents unrelated information from interfering with each other, leading to more accurate and reliable results.
