# AI-Elastic-Enrichment-Pipeline
## Summary
This project is designed to poll alerts from Elastic stack and enrich them using a local Qwen DeepSeek model. This allows quicker understanding of security alerts and speeds up triage.The system was validated using generated alerts to simulate SIEM behavior, demonstrating the full end-to-end flow of polling, cleansing, enrichment, and output delivery.
## Problem statement
Siem alerts tend to come in a massive volume and lack a large amount of context in a SOC, which leads to a lot of manual triage that takes up valuable time that could be used for an alert with higher severity. The main problem is the absence of automated reliable enrichment that can enhance the raw alerts into actionable intelligence. 
## Final Solution Overview
The final solution is an alert enrichment pipeline that retrieves alerts from Elastic using a custom python poller, which then sends the data to a webhook for enrichment by a locally hosted DeepSeek Qwen model which generates a summary block that enhances the context of the alert and structures it into a readable format. After this, the webhook receives the enhanced alert and then filters it for any possible hallucinations by enforcing a strict schema. This creates a full end-to-end flow of alert ingestion, enrichment, and delivery, which uses triggered custom alerts to validate SIEM style behavior. 
## Architecture/Tools Used
Elastic Stack (running on a dedicated VM) - This serves as the alert source for the poller and provides ECS (Elastic Common Schema) formatted security events used to validate SIEM-style ingestion.  
Poller.py - This file periodically queries Elastic for new alerts, normalizes the data, and forwards alerts to the webhook for enrichment.  
Webhook.py - This file receives the alerts from poller and forwards them to the local DeepSeek Qwen model for analysis, filters the hallucinatinos, and returns the structured enriched output block.  
Deepseek Qwen (Ran Locally using LMStudio) - Generates contextual summaries, risk insights, and enrichment data for each alert based on the prompt provided by the webhook.  
<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/2389d272-6dc5-449e-a644-bf18efe810b1" />
## Development Process
The project began with an evaluation of how SIEM alerts are structured within Elastic's ECS format. After deploying Elastic on a dedicated VM, I analyzed the alert shecma to figure out which fields were the most relevant to be enriched. After understanding the schema, I implemented a Python poller that periodically queries Elastic's alert index and normalizes incoming events.

Next, I designed the webhook service which would forward alerts to the local DeepSeek Qwen model. Initially, prompt engineering was utilized to create output consistency, which helped identify the need for a filtering layer to remove hallucinations and enforce structured responses. Once the enricher was stable, I validated the full pipeline using simulated ECS formatted alerts to ensure that the ingestion, enrichment, and output behaved as expected.
## Challenges & Solutions
A major challenge during development was the age and limitations of the virtual machine environment. The Ubuntu distribution used for Elastic and Suricata lacked several modern components and package versions along with incomplete logging features and Elastic agent had some incompatibility issues with the version used as well. A majority of the features I originally planned to utilize from Elastic were pay-only as well.

To address these constraints, I shifted from native SIEM alerts to custom Elastic alerts that were triggered by curl to trigger the conditions required for the rule to fire. This allowed Elastic to generate the ECS formatted alerts natively, enabling the poller and webhook pipeline to be validated end-to-end. The approach ensured that the system could be tested in a real environment despite the constraints and missing components in the VM distribution.
## Testing & Validation
Testing focused on each individual component of the alert-processing pipeline as well as a full test of the entire workflow. Initial validation involved attempting to generate alerts through Suricata, Filebeat, and Elastic Agent. However, several required components were missing from the utilized VM preventing these tools from producing SIEM-style events. After confirming that built-in Elastic detections could not be triggered reliably through standard security breaches, a custom detection rule was created within Elastic to serve as a controlled alert source.

Validation proceeded by using curl to trigger the condition defined in the custom alert rule, allowing Elastic to generate ECS formatted alerts natively. These alerts were successfully retrieved by the poller, confirming correct ingestion timing, schema handling, and forwarding behavior. The webhook was then tested to ensure it received alerts fromm the poller, transmitted them to the local DeepSeek Qwen model, and applied hallucination filters to produce consistent enriched and structured output. THe final validation involved reviewing the block that was returned by the webhook and analyzing each step of the system to ensure it operated correctly.
## Results
The finished pipeline successfully processed alerts end-to-end using a custom Elastic detection rule as the alert source. When the rule was triggered, the poller retrieved the ECS formatted alert and forwarded  it to the webhook without errors. The webhook transmitted the alert to the local DeepSeek Qwen model, which generated a contextual enrichment block. The filtering logic removed hallucinations and produced a clean, strucuted output. The results confirm that the pipeline operates correctly and delivers enriched alert data as intended.
## Lessons Learned
Throughout development, I learned that SIEM enviroments can be highly inconsistent depending on the operating system and available package versions. Suricata, Filebeat, and Elastic Agent lacked critical components on the Ubuntu distribution used, reinforcing the importance of validating the environment before building on top of it. I also found that custom Elastic detection rules are a reliable fallback when native rules are unavailable, allowing the pipeline to be properly tested end-to-end despite the limitations of the environment.

Using DeepSeek Qwen highlighted the need for domain-specific models in cybersecurity enrichment. While Qwen provided basic contextual information, a cybersecurity trained model would produce much more accurate and actionable insights. Additionally, strict output constraints and filtering mechanisms are a must to mitigate hallucinations and ensure consistency. Finally, building the system around a polling mechanism demonstrated the trade-offs between simplicity and real-time responsiveness, which emphasizes how future versions could benefit from event-driven ingestion. 
## Future Improvements
Long-term improvements may include universalizing the pipeline by having the poller be able to identify various available SIEM interfaces and adapt to their formatting. This would allow the pipeline to operate in many different environments without requiring manual reconfiguration or custom alerts.

Another major enhancement would involve replacing the general-purpose DeepSeek Qwen model with a cybersecurity trained LLM. This would drastically improve the level of analysis provided and heavily reduce hallucinations. With sufficient resources, the system could incorporate domain specific solution applications and advanced reasoning tailored to security operations.

Long term improvments may include containerization, real time polling, a standardized enrichment schema, or SOAR integration.


