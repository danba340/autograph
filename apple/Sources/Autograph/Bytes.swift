import Foundation

public typealias Bytes = [UInt8]

func createBytes(_ size: Int) -> Bytes {
    Bytes(repeating: 0, count: size)
}
