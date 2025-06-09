import asyncio
import httpx
import time

BASE_URL = "http://127.0.0.1:8000"  # Assuming default FastAPI run port
USERS_ENDPOINT = f"{BASE_URL}/users/"

async def fetch_users(client):
    # Helper function to make a single request
    # In a real scenario, you might want to check response status, etc.
    try:
        response = await client.get(USERS_ENDPOINT)
        response.raise_for_status() # Raise an exception for bad status codes
        return response
    except httpx.RequestError as exc:
        print(f"An error occurred while requesting {exc.request.url!r}: {exc}")
        return None

async def run_performance_test(num_requests: int, concurrency_limit: int):
    print(f"Starting performance test with {num_requests} requests and concurrency limit of {concurrency_limit}...")

    # Create an httpx.AsyncClient with connection limits
    # The limits should ideally match or be related to concurrency_limit
    # For simplicity, let's set a generous limit for now.
    limits = httpx.Limits(max_connections=concurrency_limit + 10, max_keepalive_connections=concurrency_limit)
    async with httpx.AsyncClient(limits=limits) as client:
        start_time = time.perf_counter()

        tasks = []
        for _ in range(num_requests):
            tasks.append(fetch_users(client))

        # asyncio.Semaphore can be used to strictly limit concurrency
        # However, httpx's own connection pooling (via limits) also manages concurrency.
        # For this test, we'll rely on how many tasks we launch concurrently up to num_requests
        # and how httpx handles them with its connection pool.
        # If we truly wanted to limit to 'concurrency_limit' active requests at any given time,
        # a Semaphore would be more precise.

        results = await asyncio.gather(*tasks, return_exceptions=True)

        end_time = time.perf_counter()

    total_time = end_time - start_time
    successful_requests = sum(1 for r in results if r is not None and isinstance(r, httpx.Response) and r.status_code == 200)
    failed_requests = num_requests - successful_requests

    print(f"--- Test Configuration ---")
    print(f"Target URL: {USERS_ENDPOINT}")
    print(f"Total Requests Sent: {num_requests}")
    # Note: Actual concurrency depends on httpx client's behavior and server capacity.
    # The 'concurrency_limit' here mostly influences client-side connection pool setup.
    print(f"Configured Concurrency Limit (for httpx client): {concurrency_limit}")
    print(f"--- Results ---")
    print(f"Successful Requests: {successful_requests}")
    print(f"Failed Requests: {failed_requests}")
    print(f"Total Time Taken: {total_time:.4f} seconds")

    if total_time > 0 and successful_requests > 0:
        rps = successful_requests / total_time
        print(f"Requests Per Second (RPS): {rps:.2f}")
    else:
        print("RPS: N/A (Not enough successful requests or time elapsed)")

if __name__ == "__main__":
    # Configuration for the test
    NUMBER_OF_REQUESTS = 200  # Total number of requests to send
    CONCURRENCY = 50         # How many requests to attempt to run concurrently (influences httpx client)

    # Ensure users_db is populated for GET requests to have data
    # This is tricky as this script is separate from the FastAPI app startup.
    # For now, we assume the server is running and might have some data.
    # A more robust setup might involve a setup phase to pre-populate data via API calls.

    # For this test, we'll primarily focus on the ability to handle concurrent connections
    # and process simple async requests.

    print("Reminder: Ensure the FastAPI server (`uvicorn main:app --reload`) is running before executing this script.")
    print("The /users/ endpoint will return an empty list if no users have been created on the server yet.")
    asyncio.run(run_performance_test(NUMBER_OF_REQUESTS, CONCURRENCY))
