use common::TokenBucket;

#[test]
fn test_token_bucket_precision_fix() {
    let mut bucket = TokenBucket {
        last_time: 0,
        tokens: 0,
        rate: 10_000_000, // 10MB/s (10,000,000 tokens/sec)
        capacity: 10_000_000,
        remainder: 0,
    };

    let delta = 50; // 50ns
    let iterations = 1000;
    let mut current_time = 0;

    for _ in 0..iterations {
        current_time += delta;
        bucket.refill(current_time);
    }

    // Expected:
    // Total time = 1000 * 50ns = 50,000ns
    // Tokens = 50,000 * 0.01 = 500.

    // With fix:
    // Delta * Rate = 50 * 10_000_000 = 500_000_000.
    // Iter 1: production = 500M. tokens += 0. rem = 500M.
    // Iter 2: production = 500M + 500M = 1000M. tokens += 1. rem = 0.
    // So every 2 iterations we get 1 token.
    // 1000 iterations -> 500 tokens.

    println!("Tokens accumulated: {}", bucket.tokens);

    assert_eq!(bucket.tokens, 500, "With precision fix, we should get exactly 500 tokens");
}
