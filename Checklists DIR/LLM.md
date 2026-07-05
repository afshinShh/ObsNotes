# AI Security Assessment Questionnaire


# [AI Security Assessment Questionnaire](https://github.com/Arcanum-Sec/arc_pi_taxonomy/blob/main/ai_sec_questionnaire.md)

## 1. General Information

- **AI System Name:**  
- **Organization/Team Responsible:**  
- **Primary Use Case of AI System:**  
- **Deployment Status:** 
  - [ ] Development  
  - [ ] Testing  
  - [ ] Production  
  - [ ] Decommissioning  

---

## 2. Model Security

1. **What type of AI model is used?** (e.g., LLM, computer vision, reinforcement learning, etc.)  
2. **What system or developer prompt is embedded in the model?**  
3. **Is the model proprietary, open-source, or third-party provided?**  
4. **Does the model include retrieval-augmented generation (RAG)?**  
   - [ ] Yes  
   - [ ] No  
5. **Is the model fine-tuned or zero-shot?**  
6. **Is the AI system multi-modal?**  
   - [ ] Yes  
   - [ ] No  
7. **Is the AI agentic (autonomously taking actions)?**  
   - [ ] Yes  
   - [ ] No  
8. **What tools or APIs does the AI interact with?**  

---

## 3. Storage & Data Security

1. **Where is AI-related data stored?**  
   - [ ] On-premises  
   - [ ] Cloud  
   - [ ] Hybrid  
2. **Which databases are used for model inputs, outputs, or embeddings?**  
3. **Does the system use vector databases for embeddings?**  
   - [ ] Yes  
   - [ ] No  
4. **How is data encrypted at rest and in transit?**  
5. **Are data access controls and audit logs in place?**  
   - [ ] Yes  
   - [ ] No  

---

## 4. Interface Security

1. **What type of interface is used to interact with the AI?**  
   - [ ] Chatbot  
   - [ ] API  
   - [ ] Data upload portal  
   - [ ] Other: _______  
2. **How is input data sanitized to prevent prompt injection?**  
3. **Does the AI system have rate limiting or authentication for external users?**  
   - [ ] Yes  
   - [ ] No  
4. **Is there an approval process for API integrations with external tools?**  
   - [ ] Yes  
   - [ ] No  

---

## 5. Network Architecture & Components

1. **Is the AI system exposed to external networks?**  
   - [ ] Yes  
   - [ ] No  
2. **Does it integrate with external applications?**  
   - [ ] Yes  
   - [ ] No  
   - If yes, which applications? (e.g., Salesforce, Slack, Microsoft Teams, etc.)  
3. **Does it integrate with internal applications?**  
   - [ ] Yes  
   - [ ] No  
   - If yes, does it have read/write permissions?  
     - [ ] Read  
     - [ ] Write  
     - [ ] Both  
4. **Does the AI system use open-source software (OSS)?**  
   - [ ] Yes  
   - [ ] No  
   - If yes, are dependencies monitored for vulnerabilities?  
     - [ ] Yes  
     - [ ] No  
5. **Does the system use internal APIs?**  
   - [ ] Yes  
   - [ ] No  
6. **Does it use a headless browser (e.g., Puppeteer, Selenium)?**  
   - [ ] Yes  
   - [ ] No  
7. **Is there a human-in-the-loop (HITL) component for oversight?**  
   - [ ] Yes  
   - [ ] No  

---

## 6. Development Environment Security

1. **Where is the AI training environment hosted?**  
   - [ ] On-premises  
   - [ ] Cloud  
   - [ ] Hybrid  
2. **What platform is used for prompt engineering and fine-tuning?**  
3. **What development and AI/ML tools are used?** (Select all that apply)  
   - [ ] MLflow  
   - [ ] Kubeflow  
   - [ ] Apache Airflow  
   - [ ] H2O.ai  
   - [ ] TensorFlow  
   - [ ] PyTorch  
   - [ ] AI-as-a-Service (Amazon SageMaker, Azure ML, Google Vertex AI, etc.)  
   - [ ] Other: __________  
4. **How is identity and access management (IAM) handled for developers?**  
5. **Are AI-related workloads isolated from general IT infrastructure?**  
   - [ ] Yes  
   - [ ] No  

---

## 7. AI Supply Chain Security

1. **Does the AI system use third-party AI models or datasets?**  
   - [ ] Yes  
   - [ ] No  
2. **Are security controls in place for model registries?**  
   - [ ] Yes  
   - [ ] No  
3. **Is there a process to detect backdoored or malicious AI models?**  
   - [ ] Yes  
   - [ ] No  
4. **Are virtual machines, containers, and AI platforms hardened against exploits?**  
   - [ ] Yes  
   - [ ] No  
5. **Has the AI system undergone a supply chain security assessment?**  
   - [ ] Yes  
   - [ ] No  
6. **Are Docker images used, and if so, are they verified for security?**  
   - [ ] Yes  
   - [ ] No  

---

## 8. Bias, Safety, and Accuracy

1. **Is bias a concern for this AI system?**  
   - [ ] Yes  
   - [ ] No  
2. **Are fairness and ethical considerations documented?**  
   - [ ] Yes  
   - [ ] No  
3. **Does the AI system make decisions with potential legal or financial impact?**  
   - [ ] Yes  
   - [ ] No  
4. **Has the AI been tested for biases in race, gender, age, or other factors?**  
   - [ ] Yes  
   - [ ] No  
5. **Can the AI system be manipulated into providing unfair advantages (e.g., forced discounts)?**  
   - [ ] Yes  
   - [ ] No  
6. **What safeguards are in place to prevent harmful outputs?**  

---

## 9. Security Testing & Incident Response

1. **Has the AI system undergone security penetration testing?**  
   - [ ] Yes  
   - [ ] No  
2. **Is there an incident response plan specific to AI-related attacks?**  
   - [ ] Yes  
   - [ ] No  
3. **Are AI-generated outputs monitored for anomalies?**  
   - [ ] Yes  
   - [ ] No  
4. **What methods are used to detect adversarial attacks or prompt injection?**  
5. **Are security patches and model updates tracked and applied?**  
   - [ ] Yes  
   - [ ] No  


# [LLM Threat Modeling Questions](https://github.com/Arcanum-Sec/arc_pi_taxonomy/blob/main/ai_threat_model_questions.md)

## 1. System Inputs & Entry Points
1. What are all the interfaces through which users can submit prompts to the LLM?
2. Are there any indirect input vectors (file uploads, document processing, etc.)?
3. How is user authentication handled for different input channels?
4. What input validation exists at each entry point?

## 2. Ecosystem Vulnerabilities
1. What third-party components make up the LLM system's ecosystem?
2. How are dependencies and libraries secured and updated?
3. Are there vulnerabilities in the hosting infrastructure?
4. What network attack surfaces exist in the system's ecosystem?

## 3. Model Security
1. Is this a proprietary, open-source, or third-party provided LLM?
2. What known model vulnerabilities or weaknesses exist?
3. Is the model susceptible to adversarial attacks or jailbreaking techniques?
4. How is the model protected against inference manipulation?

## 4. Prompt Engineering Security
1. How are system prompts and instructions secured?
2. What measures prevent prompt injection attacks?
3. Are there filtering mechanisms for malicious instruction attempts?
4. Could prompt leakage expose sensitive system configurations?

## 5. Data Security
1. What sensitive data might be processed by the LLM?
2. How is training, fine-tuning, and user data secured?
3. Are vector databases or embeddings protected against leakage?
4. What data retention and deletion policies are in place?

## 6. Application Security
1. How is the application layer (frontend, API) secured?
2. What authentication and authorization controls exist?
3. Are there rate limits and abuse prevention mechanisms?
4. How is the application monitored for unusual behavior?

## 7. Pivoting Potential
1. Could the LLM be used to pivot to other systems?
2. What lateral movement paths exist if one component is compromised?
3. Does the LLM have access or connections to sensitive internal systems?
4. What is the blast radius if a compromise occurs?

## 8. Monitoring & Response
1. How are attacks against each vector detected and alerted?
2. Is there a specific incident response plan for LLM-related security events?
3. How are security logs collected and analyzed?
4. What is the process for addressing new attack techniques?

# [Defending AI Systems Checklist](https://github.com/Arcanum-Sec/arc_pi_taxonomy/blob/main/ai_enabled_app_defense_checklist.md)

## Defense Inspired by Attack Layers

### Layer One (Ecosystem): Securing AI infrastructure and cloud environments
- [ ] Keep open source software up to date with patches
- [ ] Ensure no security vulnerabilities are latent
- [ ] Enable two-factor Authentication for dashboards and GUIs
- [ ] Configure IAM roles for Cloud infrastructure
- [ ] Consider using a multi-LLM system with intermediary agents for data transformation
- [ ] Add comprehensive monitoring for unusual access/excess patterns and anomalous requests
- [ ] Secure logs and dashboards from javascript-based attacks, executing code, or following links

### Layer Two (Model): Protecting AI models from poisoning and adversarial attacks
- [ ] Choose a frontier model with strong guardrails
- [ ] Tune an OSS model to reduce bias, harm, and other undesirable outputs
- [ ] Add external defenses for prompt injection and jailbreaks
- [ ] Work with legal and PR to add a legal disclaimer for publicly available AI-enabled systems
- [ ] Implement regular security testing or apply a bug bounty

### Layer Three (Prompt): Preventing prompt injection and response manipulation
- [ ] Add system prompt based defenses
- [ ] Do not store API keys, secret routes, PII, or proprietary private information in system prompts
- [ ] Implement rate limiting to restrict submission frequency and complexity
- [ ] Manage context window size and information retention when possible

### Layer Four (Data): Safeguarding training and inference data from corruption
- [ ] Ensure data is scrubbed of private information before it enters the RAG system (including metadata)
- [ ] Ensure all enabled tools and agents that interact with APIs have scoped roles
- [ ] Configure tools and agents to access only the minimum data needed for operational goals
- [ ] Make tools and agents that interact with APIs read-only when possible

### Layer Five (Application): Hardening AI-integrated applications and APIs
- [ ] Ensure robust input validation and output encoding on all input sources:
  - [ ] Forms
  - [ ] API requests
  - [ ] File uploads
  - [ ] Input from integrations with other systems
- [ ] Prevent verbose logging to web sockets or debug consoles
- [ ] Implement sandboxing to isolate AI components from critical systems, especially multimodal systems (SSRF)

# References
- **[The Arcanum Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy)**
- 