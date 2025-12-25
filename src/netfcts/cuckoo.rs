use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Cuckoo hash table optimized for socket (IP, Port) -> Value mapping
/// Uses 2 hash functions and achieves O(1) average lookup time
pub struct CuckooSocketMap<V> {
    /// Primary table
    table1: Vec<Entry<V>>,
    /// Secondary table
    table2: Vec<Entry<V>>,
    /// Number of occupied slots
    count: usize,
    /// Capacity of each table (power of 2 for fast modulo)
    capacity: usize,
    /// Mask for fast modulo (capacity - 1)
    mask: usize,
    /// Maximum number of relocations before resize
    max_kicks: usize,
}

#[derive(Clone, Copy, Debug)]
struct Entry<V> {
    /// Socket: (IP address, port)
    key: (u32, u16),
    /// Value assigned to this socket
    value: V,
    /// true if slot is occupied
    occupied: bool,
}

impl<V: Default + Copy> Entry<V> {
    #[inline]
    fn empty() -> Self {
        Entry {
            key: (0, 0),
            value: V::default(),
            occupied: false,
        }
    }

    #[inline]
    fn new(key: (u32, u16), value: V) -> Self {
        Entry {
            key,
            value,
            occupied: true,
        }
    }
}

impl<V: Default + Copy> CuckooSocketMap<V> {
    /// Creates a new CuckooSocketMap with the specified capacity
    /// Capacity will be rounded up to next power of 2
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        Self {
            table1: vec![Entry::empty(); capacity],
            table2: vec![Entry::empty(); capacity],
            count: 0,
            capacity,
            mask: capacity - 1,
            max_kicks: 500, // Maximum relocations before giving up
        }
    }

    /// Hash function 1: Uses IP address primarily
    #[inline]
    fn hash1(&self, key: &(u32, u16)) -> usize {
        let mut hasher = DefaultHasher::new();
        key.0.hash(&mut hasher);
        key.1.hash(&mut hasher);
        (hasher.finish() as usize) & self.mask
    }

    /// Hash function 2: Uses port primarily and XOR with IP
    #[inline]
    fn hash2(&self, key: &(u32, u16)) -> usize {
        let mut hasher = DefaultHasher::new();
        (key.0 ^ (key.1 as u32)).hash(&mut hasher);
        key.1.rotate_left(8).hash(&mut hasher);
        (hasher.finish() as usize) & self.mask
    }

    /// Returns the number of entries in the map
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the map is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the load factor (0.0 to 1.0)
    #[inline]
    pub fn load_factor(&self) -> f64 {
        self.count as f64 / (self.capacity * 2) as f64
    }

    /// Lookup a socket in the hash table
    /// Returns Some(value) if found, None otherwise
    /// Guaranteed O(1) - max 2 lookups
    #[inline]
    pub fn get(&self, key: &(u32, u16)) -> Option<V> {
        let idx1 = self.hash1(key);
        let entry1 = &self.table1[idx1];
        if entry1.occupied && entry1.key == *key {
            return Some(entry1.value);
        }

        let idx2 = self.hash2(key);
        let entry2 = &self.table2[idx2];
        if entry2.occupied && entry2.key == *key {
            return Some(entry2.value);
        }

        None
    }

    /// Insert or update a socket mapping
    /// Returns Some(old_value) if key existed, None otherwise
    pub fn insert(&mut self, key: (u32, u16), value: V) -> Option<V> {
        // Check if key already exists and update
        let idx1 = self.hash1(&key);
        if self.table1[idx1].occupied && self.table1[idx1].key == key {
            let old = self.table1[idx1].value;
            self.table1[idx1].value = value;
            return Some(old);
        }

        let idx2 = self.hash2(&key);
        if self.table2[idx2].occupied && self.table2[idx2].key == key {
            let old = self.table2[idx2].value;
            self.table2[idx2].value = value;
            return Some(old);
        }

        // Check load factor and resize if needed (>85% full)
        if self.load_factor() > 0.85 {
            self.resize();
        }

        // Try to insert in table1
        if !self.table1[idx1].occupied {
            self.table1[idx1] = Entry::new(key, value);
            self.count += 1;
            return None;
        }

        // Try to insert in table2
        if !self.table2[idx2].occupied {
            self.table2[idx2] = Entry::new(key, value);
            self.count += 1;
            return None;
        }

        // Both positions occupied, start cuckoo relocation
        self.cuckoo_insert(key, value)
    }

    /// Cuckoo insertion with relocation
    fn cuckoo_insert(&mut self, mut key: (u32, u16), mut value: V) -> Option<V> {
        let mut current_table = 1; // Start with table1

        for _ in 0..self.max_kicks {
            let idx = if current_table == 1 {
                self.hash1(&key)
            } else {
                self.hash2(&key)
            };

            // Swap with existing entry
            let table = if current_table == 1 {
                &mut self.table1
            } else {
                &mut self.table2
            };

            let old_entry = table[idx];
            table[idx] = Entry::new(key, value);

            if !old_entry.occupied {
                // Found empty slot
                self.count += 1;
                return None;
            }

            // Continue with evicted entry
            key = old_entry.key;
            value = old_entry.value;
            current_table = 3 - current_table; // Toggle between 1 and 2
        }

        // Failed to insert after max_kicks, need to resize
        self.resize();
        self.insert(key, value)
    }

    /// Remove a socket mapping
    /// Returns Some(value) if found and removed, None otherwise
    pub fn remove(&mut self, key: &(u32, u16)) -> Option<V> {
        let idx1 = self.hash1(key);
        if self.table1[idx1].occupied && self.table1[idx1].key == *key {
            let value = self.table1[idx1].value;
            self.table1[idx1] = Entry::empty();
            self.count -= 1;
            return Some(value);
        }

        let idx2 = self.hash2(key);
        if self.table2[idx2].occupied && self.table2[idx2].key == *key {
            let value = self.table2[idx2].value;
            self.table2[idx2] = Entry::empty();
            self.count -= 1;
            return Some(value);
        }

        None
    }

    /// Resize the hash table (doubles capacity)
    fn resize(&mut self) {
        let old_table1 = std::mem::replace(&mut self.table1, Vec::new());
        let old_table2 = std::mem::replace(&mut self.table2, Vec::new());

        let new_capacity = self.capacity * 2;
        self.capacity = new_capacity;
        self.mask = new_capacity - 1;
        self.table1 = vec![Entry::empty(); new_capacity];
        self.table2 = vec![Entry::empty(); new_capacity];
        self.count = 0;

        // Re-insert all entries
        for entry in old_table1.iter().chain(old_table2.iter()) {
            if entry.occupied {
                self.insert(entry.key, entry.value);
            }
        }
    }

    /// Iterator over all (key, value) pairs
    pub fn iter(&self) -> impl Iterator<Item = ((u32, u16), V)> + '_ {
        self.table1
            .iter()
            .chain(self.table2.iter())
            .filter(|e| e.occupied)
            .map(|e| (e.key, e.value))
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        for entry in self.table1.iter_mut() {
            *entry = Entry::empty();
        }
        for entry in self.table2.iter_mut() {
            *entry = Entry::empty();
        }
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_get() {
        let mut map = CuckooSocketMap::<u16>::new(16);

        map.insert((192_168_1_1, 8080), 1234);
        map.insert((192_168_1_2, 8081), 1235);

        assert_eq!(map.get(&(192_168_1_1, 8080)), Some(1234));
        assert_eq!(map.get(&(192_168_1_2, 8081)), Some(1235));
        assert_eq!(map.get(&(192_168_1_3, 8082)), None);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_update() {
        let mut map = CuckooSocketMap::<u16>::new(16);

        assert_eq!(map.insert((192_168_1_1, 8080), 1234), None);
        assert_eq!(map.insert((192_168_1_1, 8080), 5678), Some(1234));
        assert_eq!(map.get(&(192_168_1_1, 8080)), Some(5678));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut map = CuckooSocketMap::<u16>::new(16);

        map.insert((192_168_1_1, 8080), 1234);
        assert_eq!(map.remove(&(192_168_1_1, 8080)), Some(1234));
        assert_eq!(map.get(&(192_168_1_1, 8080)), None);
        assert_eq!(map.remove(&(192_168_1_1, 8080)), None);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_many_insertions() {
        let mut map = CuckooSocketMap::<u16>::new(64);

        // Insert 1000 entries
        for i in 0..1000u16 {
            let ip = 192_168_0_0 + i as u32;
            let port = 8000 + i;
            map.insert((ip, port), i);
        }

        assert_eq!(map.len(), 1000);

        // Verify all entries
        for i in 0..1000u16 {
            let ip = 192_168_0_0 + i as u32;
            let port = 8000 + i;
            assert_eq!(map.get(&(ip, port)), Some(i));
        }

        println!("Load factor after 1000 insertions: {:.2}", map.load_factor());
    }

    #[test]
    fn test_resize() {
        let mut map = CuckooSocketMap::<u16>::new(4);

        // Force multiple resizes
        for i in 0..100u16 {
            map.insert((i as u32, i), i);
        }

        assert_eq!(map.len(), 100);

        // Verify all entries still accessible
        for i in 0..100u16 {
            assert_eq!(map.get(&(i as u32, i)), Some(i));
        }
    }

    #[test]
    fn test_clear() {
        let mut map = CuckooSocketMap::<u16>::new(16);

        for i in 0..10u16 {
            map.insert((i as u32, i), i);
        }

        assert_eq!(map.len(), 10);
        map.clear();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert_eq!(map.get(&(5, 5)), None);
    }

    #[test]
    fn test_collision_handling() {
        let mut map = CuckooSocketMap::<u16>::new(8);

        // Insert many entries that may cause collisions
        for i in 0..50u16 {
            let ip = 192_168_1_1;
            let port = 8000 + i;
            map.insert((ip, port), i);
        }

        // Verify all entries
        for i in 0..50u16 {
            let ip = 192_168_1_1;
            let port = 8000 + i;
            assert_eq!(map.get(&(ip, port)), Some(i), "Failed at index {}", i);
        }
    }
}