import Random "mo:base/Random";
import Blob "mo:base/Blob";
import Array "mo:base/Array";

actor {
    public func generateRandomNumber() : async [Nat8] {
        let randomBlob = await Random.blob(); 
        let random = Blob.toArray(randomBlob);
        return Array.subArray(random, 0, 16); 
    }
}