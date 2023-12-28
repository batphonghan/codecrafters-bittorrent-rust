pub struct TrackerRequest {
    ///the info hash of the torrent
    /// 20 bytes long, will need to be URL encoded
    /// Note: this is NOT the hexadecimal representation, which is 40 bytes long
    info_hash: String,

    /// peer_id: a unique identifier for your client
    /// A string of length 20 that you get to pick. You can use something like 00112233445566778899.
    peer_id: String,

    /// port: the port your client is listening on
    /// You can set this to 6881, you will not have to support this functionality during this challenge.
    port: u8,

    /// uploaded: the total amount uploaded so far
    /// Since your client hasn't uploaded anything yet, you can set this to 0.
    uploaded: i64,

    // downloaded: the total amount downloaded so far
    // Since your client hasn't downloaded anything yet, you can set this to 0.
    downloaded: i64,

    // left: the number of bytes left to download
    // Since you client hasn't downloaded anything yet, this'll be the total length of the file (you've extracted this value from the torrent file in previous stages)
    left: i64,

    // compact: whether the peer list should use the compact representation
    // For the purposes of this challenge, set this to 1.
    // The compact representation is more commonly used in the wild, the non-compact representation is mostly supported for backward-compatibility.
    compact: u8,
}
