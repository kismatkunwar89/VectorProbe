"""
Custom decorators for the Network Enumeration Tool.

This module demonstrates Python decorator patterns for:
- Input validation
- Retry logic
- Timing/profiling
- Logging
"""

import time
import logging
import functools
from typing import Callable, Any

from utils.validation import is_valid_ip

logger = logging.getLogger(__name__)


def validate_ip(func: Callable) -> Callable:
    """
    Decorator that validates IP address input before executing the function.

    Checks if the first positional argument after 'self' is a valid IP address.
    Raises ValueError if the IP is invalid.

    Example:
        @validate_ip
        def scan_host(self, ip: str):
            # ip is guaranteed to be valid here
            pass

    Args:
        func: The function to decorate

    Returns:
        Wrapped function with IP validation

    Raises:
        ValueError: If the IP address is invalid
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Get the IP argument (assuming it's the first arg after self)
        if len(args) > 1:
            ip = args[1]
            if not is_valid_ip(ip):
                raise ValueError(f"Invalid IP address: {ip}")

        return func(*args, **kwargs)

    return wrapper


def retry(max_attempts: int = 3, delay: float = 1.0):
    """
    Decorator that retries a function if it raises an exception.

    Useful for network operations that might fail temporarily.

    Example:
        @retry(max_attempts=3, delay=2.0)
        def fetch_data(self, url):
            # This will retry up to 3 times with 2 second delays
            return requests.get(url)

    Args:
        max_attempts: Maximum number of attempts (default: 3)
        delay: Delay in seconds between attempts (default: 1.0)

    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts:
                        logger.warning(
                            f"Attempt {attempt}/{max_attempts} failed for {func.__name__}: {e}. "
                            f"Retrying in {delay}s..."
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"All {max_attempts} attempts failed for {func.__name__}: {e}"
                        )

            # If all attempts failed, raise the last exception
            raise last_exception

        return wrapper
    return decorator


def timing(func: Callable) -> Callable:
    """
    Decorator that logs the execution time of a function.

    Useful for profiling slow operations like network scans.

    Example:
        @timing
        def scan_network(self, targets):
            # Execution time will be logged
            pass

    Args:
        func: The function to decorate

    Returns:
        Wrapped function that logs execution time
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()

        elapsed = end_time - start_time
        logger.info(f"{func.__name__} completed in {elapsed:.2f} seconds")

        return result

    return wrapper


def log_calls(func: Callable) -> Callable:
    """
    Decorator that logs function calls with arguments.

    Useful for debugging and understanding program flow.

    Example:
        @log_calls
        def process_target(self, ip, port):
            # Function call will be logged
            pass

    Args:
        func: The function to decorate

    Returns:
        Wrapped function that logs calls
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Format arguments for logging
        args_repr = [repr(a) for a in args[1:]]  # Skip 'self'
        kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]
        signature = ", ".join(args_repr + kwargs_repr)

        logger.debug(f"Calling {func.__name__}({signature})")
        result = func(*args, **kwargs)
        logger.debug(f"{func.__name__} returned {result!r}")

        return result

    return wrapper


# Example of stacking decorators
def validated_timed_scan(func: Callable) -> Callable:
    """
    Combines validation and timing decorators.

    Example of decorator composition.

    Args:
        func: The function to decorate

    Returns:
        Function with both validation and timing
    """
    return timing(validate_ip(func))
