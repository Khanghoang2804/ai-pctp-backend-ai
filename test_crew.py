from crewai import Agent, Task, Crew, Process, LLM
import logging
import io

log_stream = io.StringIO()
logging.basicConfig(stream=log_stream, level=logging.DEBUG)

llm = LLM(model="openai/gpt-4o-mini", api_key="sk-test", base_url="https://ckey.vn/v1")
agent = Agent(role='test', goal='test', backstory='test', llm=llm, verbose=True)
task = Task(description='test', expected_output='test', agent=agent)
crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=True)

try:
    crew.kickoff()
except Exception as e:
    print("ERROR:", e)

print("CAPTURED LOGS LENGTH:", len(log_stream.getvalue()))
print(log_stream.getvalue()[:200])
