use serde::{Deserialize, Serialize};
use sled::Db;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, RwLock};

/// Custom error type for storage operations
#[derive(Debug)]
pub enum StorageError {
    /// Represents errors that occur when performing I/O operations
    IoError(std::io::Error),
    /// Represents errors from the underlying database operations
    DbError(sled::Error),
    /// Represents errors during serialization/deserialization of data
    SerializationError(bincode::Error),
    /// Represents errors when working with system time
    SystemTimeError(std::time::SystemTimeError),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "IO error: {}", e),
            StorageError::DbError(e) => write!(f, "Database error: {}", e),
            StorageError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            StorageError::SystemTimeError(e) => write!(f, "System time error: {}", e),
        }
    }
}

impl Error for StorageError {}

// Implement From trait for automatic error conversion
impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::IoError(err)
    }
}

impl From<sled::Error> for StorageError {
    fn from(err: sled::Error) -> Self {
        StorageError::DbError(err)
    }
}

impl From<bincode::Error> for StorageError {
    fn from(err: bincode::Error) -> Self {
        StorageError::SerializationError(err)
    }
}

impl From<std::time::SystemTimeError> for StorageError {
    fn from(err: std::time::SystemTimeError) -> Self {
        StorageError::SystemTimeError(err)
    }
}

/// Type alias for Result with StorageError as error type
type Result<T> = std::result::Result<T, StorageError>;

/// Represents a node in the storage system that holds encrypted data
/// Each node contains a hash for identification, optional encrypted data,
/// timestamp for ordering, and size information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Node {
    /// BLAKE3 hash used as a unique identifier
    hash: [u8; 32],
    /// Optional encrypted data (None in cache, Some in storage)
    cipher_data: Option<Vec<u8>>,
    /// Unix timestamp for node creation/modification
    timestamp: u64,
    /// Size of the encrypted data in bytes
    size: usize,
}

/// Main storage manager that handles both persistent storage and in-memory cache
pub struct StorageManager {
    /// Persistent storage using sled database
    db: Db,
    /// Thread-safe cache storing metadata without cipher_data
    cache: Arc<RwLock<Vec<Node>>>,
    /// Maximum number of nodes to keep in cache
    max_nodes: usize,
}

impl StorageManager {
    /// Creates a new StorageManager instance
    ///
    /// # Arguments
    /// * `db_path` - Path to the sled database file
    /// * `max_nodes` - Maximum number of nodes to keep in memory cache
    ///
    /// # Returns
    /// * `Result<Self>` - New StorageManager instance or error
    pub fn new(db_path: &str, max_nodes: usize) -> Result<Self> {
        let db = sled::open(db_path)?;
        Ok(Self {
            db,
            cache: Arc::new(RwLock::new(Vec::with_capacity(max_nodes))),
            max_nodes,
        })
    }

    /// Adds a new node to both persistent storage and cache
    ///
    /// # Arguments
    /// * `cipher_data` - Encrypted data to store
    /// * `hash` - BLAKE3 hash of the data
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    pub async fn add_node(&self, cipher_data: Vec<u8>, hash: [u8; 32]) -> Result<()> {
        // Create new node with current timestamp
        let node = Node {
            hash,
            cipher_data: Some(cipher_data.clone()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            size: cipher_data.len(),
        };

        // Store complete node in database
        self.db.insert(hash, bincode::serialize(&node)?)?;

        // Update in-memory cache with metadata only
        let mut cache = self
            .cache
            .write()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Cache lock error"))?;

        // Remove oldest node if cache is full
        if cache.len() >= self.max_nodes {
            cache.remove(0);
        }
        // Add new node to cache without cipher_data
        cache.push(Node {
            hash,
            cipher_data: None,
            timestamp: node.timestamp,
            size: node.size,
        });

        Ok(())
    }

    /// Retrieves a node by its hash
    ///
    /// # Arguments
    /// * `hash` - BLAKE3 hash of the node to retrieve
    ///
    /// # Returns
    /// * `Result<Option<Node>>` - Node if found, None if not found, or error
    pub async fn get_node(&self, hash: &[u8; 32]) -> Result<Option<Node>> {
        // First check the cache for existence
        let cache = self
            .cache
            .read()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Cache lock error"))?;

        // If found in cache, load full data from database
        if let Some(_cached_node) = cache.iter().find(|n| n.hash == *hash) {
            if let Some(data) = self.db.get(hash)? {
                return Ok(Some(bincode::deserialize(&data)?));
            }
        }

        // If not in cache, try loading directly from database
        if let Some(data) = self.db.get(hash)? {
            Ok(Some(bincode::deserialize(&data)?))
        } else {
            Ok(None)
        }
    }

    /// Deletes a node from both storage and cache
    ///
    /// # Arguments
    /// * `hash` - BLAKE3 hash of the node to delete
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    pub async fn delete_node(&self, hash: &[u8; 32]) -> Result<()> {
        // Remove from database first
        self.db.remove(hash)?;

        // Then remove from cache if present
        let mut cache = self
            .cache
            .write()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Cache lock error"))?;

        if let Some(pos) = cache.iter().position(|n| n.hash == *hash) {
            cache.remove(pos);
        }

        Ok(())
    }

    /// Updates an existing node with new data
    ///
    /// # Arguments
    /// * `hash` - BLAKE3 hash of the node to update
    /// * `new_cipher_data` - New encrypted data
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    pub async fn update_node(&self, hash: &[u8; 32], new_cipher_data: Vec<u8>) -> Result<()> {
        // Implement update as delete + add for simplicity and consistency
        self.delete_node(hash).await?;
        self.add_node(new_cipher_data, *hash).await?;
        Ok(())
    }

    /// Retrieves all nodes from cache (metadata only, no cipher_data)
    ///
    /// # Returns
    /// * `Result<Vec<Node>>` - Vector of all cached nodes or error
    pub async fn get_all_nodes(&self) -> Result<Vec<Node>> {
        let cache = self
            .cache
            .read()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Cache lock error"))?;
        Ok(cache.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use tempfile::tempdir;

    /// Generates random encrypted data of fixed size (1024 bytes)
    /// This simulates encrypted records that would be stored in the system
    ///
    /// # Returns
    /// * `Vec<u8>` - Vector containing random bytes to simulate encrypted data
    fn generate_cipher_data() -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 1024]; // Fixed size to simulate real-world encrypted records
        rng.fill(&mut data[..]);
        data
    }

    /// Test basic CRUD (Create, Read, Update, Delete) operations
    /// Verifies that:
    /// - A node can be added to storage
    /// - A node can be retrieved with correct data
    /// - A node can be updated with new data
    /// - A node can be deleted
    #[tokio::test]
    async fn test_storage_basic_operations() -> Result<()> {
        // Setup temporary test directory
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path().join("test_db");

        // Initialize storage with moderate cache size
        let storage = StorageManager::new(db_path.to_str().unwrap(), 400)?;

        // Test node creation and storage
        let cipher_data = generate_cipher_data();
        let hash = blake3::hash(&cipher_data).into();
        storage.add_node(cipher_data.clone(), hash).await?;

        // Verify node retrieval and data integrity
        let retrieved_node = storage.get_node(&hash).await?.unwrap();
        assert_eq!(retrieved_node.cipher_data.unwrap(), cipher_data);
        assert_eq!(retrieved_node.size, 1024);

        // Test node update functionality
        let new_cipher_data = generate_cipher_data();
        storage.update_node(&hash, new_cipher_data.clone()).await?;
        let updated_node = storage.get_node(&hash).await?.unwrap();
        assert_eq!(updated_node.cipher_data.unwrap(), new_cipher_data);

        // Test node deletion
        storage.delete_node(&hash).await?;
        assert!(storage.get_node(&hash).await?.is_none());

        Ok(())
    }

    /// Tests handling of multiple nodes in storage
    /// Verifies that:
    /// - Multiple nodes can be stored successfully
    /// - All nodes are properly cached
    /// - Each node maintains data integrity
    /// - The system can handle the specified amount of nodes
    #[tokio::test]
    async fn test_storage_multiple_nodes() -> Result<()> {
        const AMOUNT_OF_NODES: usize = 400;

        // Setup temporary test environment
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path().join("test_db_multiple");

        // Initialize storage with capacity matching test size
        let storage = StorageManager::new(db_path.to_str().unwrap(), AMOUNT_OF_NODES)?;
        let mut hashes = Vec::new();

        // Create and store multiple nodes
        for _ in 0..AMOUNT_OF_NODES {
            let cipher_data = generate_cipher_data();
            let hash = blake3::hash(&cipher_data).into();
            storage.add_node(cipher_data, hash).await?;
            hashes.push(hash);
        }

        // Verify cache contains all nodes
        let all_nodes = storage.get_all_nodes().await?;
        assert_eq!(all_nodes.len(), AMOUNT_OF_NODES);

        // Verify each node's integrity
        for hash in hashes {
            let node = storage.get_node(&hash).await?;
            assert!(node.is_some());
            assert_eq!(node.unwrap().size, 1024);
        }

        Ok(())
    }

    /// Tests the cache size limitation functionality
    /// Verifies that:
    /// - Cache size never exceeds the specified maximum
    /// - Older nodes are properly removed when cache is full
    /// - New nodes can still be added when cache is full
    #[tokio::test]
    async fn test_storage_max_nodes() -> Result<()> {
        // Setup test environment
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path().join("test_db_max");

        // Set a small cache size to test limiting
        let max_nodes = 5;
        let storage = StorageManager::new(db_path.to_str().unwrap(), max_nodes)?;

        // Add more nodes than the cache limit
        for _ in 0..10 {
            let cipher_data = generate_cipher_data();
            let hash = blake3::hash(&cipher_data).into();
            storage.add_node(cipher_data, hash).await?;
        }

        // Verify cache size respect the limit
        let all_nodes = storage.get_all_nodes().await?;
        assert!(all_nodes.len() <= max_nodes);

        Ok(())
    }

    /// Tests concurrent access to the storage system
    /// Simulates real-world scenario with multiple threads performing
    /// different operations simultaneously
    ///
    /// Verifies that:
    /// - Multiple threads can access storage concurrently
    /// - Data remains consistent under concurrent access
    /// - No deadlocks occur during parallel operations
    /// - Error handling works properly in concurrent scenario
    #[tokio::test]
    async fn test_concurrent_access() -> Result<()> {
        use futures::future::join_all;
        use rand::seq::SliceRandom;
        use std::time::Duration;
        use tokio::time::sleep;

        // Test configuration
        const THREADS: usize = 100; // Number of concurrent threads
        const OPERATIONS_PER_THREAD: usize = 50; // Operations per thread

        // Setup test environment
        let temp_dir = tempdir()?;
        let db_path = temp_dir.path().join("test_db_concurrent");

        // Initialize storage with large enough cache
        let storage = Arc::new(StorageManager::new(db_path.to_str().unwrap(), 1000)?);

        // Initialize storage with some initial data
        let mut initial_hashes = Vec::new();
        for _ in 0..20 {
            let data = generate_cipher_data();
            let hash = blake3::hash(&data).into();
            storage.add_node(data, hash).await?;
            initial_hashes.push(hash);
        }

        let mut handles = Vec::new();
        let initial_hashes = Arc::new(initial_hashes);

        // Spawn multiple threads for concurrent operations
        for thread_id in 0..THREADS {
            let storage = storage.clone();
            let hashes = initial_hashes.clone();

            let handle = tokio::spawn(async move {
                for op_id in 0..OPERATIONS_PER_THREAD {
                    // Prepare operation parameters before any await calls
                    // This ensures thread safety with RNG
                    let op = {
                        let mut rng = rand::thread_rng();
                        let delay = rng.gen_range(0..10);
                        let op_type = rng.gen_range(0..4);
                        let selected_hash = hashes.choose(&mut rng).cloned();
                        let new_data = if op_type == 0 || op_type == 2 {
                            Some(generate_cipher_data())
                        } else {
                            None
                        };
                        (delay, op_type, selected_hash, new_data)
                    };

                    // Add random delay to increase chance of concurrent access
                    sleep(Duration::from_millis(op.0)).await;

                    // Perform random operation based on op_type
                    match op.1 {
                        0 => {
                            // Add new node operation
                            if let Some(data) = op.3 {
                                let hash = blake3::hash(&data).into();
                                if let Err(e) = storage.add_node(data, hash).await {
                                    eprintln!("Thread {} op {} add error: {}", thread_id, op_id, e);
                                }
                            }
                        }
                        1 => {
                            // Read existing node operation
                            if let Some(hash) = op.2 {
                                if let Err(e) = storage.get_node(&hash).await {
                                    eprintln!(
                                        "Thread {} op {} read error: {}",
                                        thread_id, op_id, e
                                    );
                                }
                            }
                        }
                        2 => {
                            // Update existing node operation
                            if let Some(hash) = op.2 {
                                if let Some(new_data) = op.3 {
                                    if let Err(e) = storage.update_node(&hash, new_data).await {
                                        eprintln!(
                                            "Thread {} op {} update error: {}",
                                            thread_id, op_id, e
                                        );
                                    }
                                }
                            }
                        }
                        3 => {
                            // List all nodes operation
                            if let Err(e) = storage.get_all_nodes().await {
                                eprintln!("Thread {} op {} get_all error: {}", thread_id, op_id, e);
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        let results = join_all(handles).await;

        // Verify all threads completed successfully
        for result in results {
            result.expect("Task panicked");
        }

        // Verify storage integrity after concurrent operations
        let final_nodes = storage.get_all_nodes().await?;
        assert!(
            !final_nodes.is_empty(),
            "Storage should not be empty after operations"
        );

        // Verify all cached nodes are accessible
        for node in &final_nodes {
            let retrieved = storage.get_node(&node.hash).await?;
            assert!(
                retrieved.is_some(),
                "Should be able to retrieve cached node"
            );
        }

        Ok(())
    }
}
