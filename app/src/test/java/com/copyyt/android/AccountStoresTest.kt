package com.copyyt.android

import com.copyyt.android.crypto.DeviceKeys
import com.copyyt.android.net.CopyytJson
import com.copyyt.android.net.DeviceDto
import com.copyyt.android.store.IdentityStore
import com.copyyt.android.store.InMemoryStorage
import com.copyyt.android.trust.LocalDevice
import com.copyyt.android.trust.LocalTrust
import com.copyyt.android.trust.TrustStore
import kotlinx.serialization.builtins.ListSerializer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class AccountStoresTest {
    private val storage = InMemoryStorage()

    private fun device(id: String) = DeviceKeys.generate().let {
        DeviceDto(id, id, "chrome", it.encryptionPublicKeyBase64, it.signingPublicKeyBase64, "trusted", 1)
    }

    @Test
    fun eachAccountKeepsItsOwnIdentity() {
        val store = IdentityStore(storage)
        val first = store.getOrCreate("user-a")
        store.getOrCreate("user-b")
        assertEquals(first.deviceId, store.getOrCreate("user-a").deviceId)

        store.clear("user-b")
        assertNull(store.get("user-b"))
        assertEquals(first.deviceId, store.get("user-a")!!.deviceId)
    }

    @Test
    fun aSingleAccountIdentityFromEarlierVersionsIsKept() {
        val keys = DeviceKeys.generate()
        val legacy = """{"userId":"user-a","deviceId":"device-1","signingSeed":"${
            com.copyyt.android.protocol.B64.encode(keys.signingSeed)
        }","encryptionPrivateKey":"${
            com.copyyt.android.protocol.B64.encode(keys.encryptionPrivateKey)
        }","keyVersion":3}"""
        storage.write("identity", legacy.toByteArray())

        val store = IdentityStore(storage)
        assertNull(store.get("user-b"))
        val migrated = store.get("user-a")!!
        assertEquals("device-1", migrated.deviceId)
        assertEquals(3, migrated.keyVersion)
        assertNull(storage.read("identity"))
    }

    @Test
    fun trustIsLoadedOnlyForTheSignedInAccount() {
        val store = TrustStore(storage)
        store.upsertServerReported("user-a", device("chrome-a"))
        store.upsertServerReported("user-b", device("chrome-b"))
        assertEquals(listOf("chrome-b"), store.all().map { it.deviceId })

        store.clear()
        store.useAccount("user-a")
        assertEquals(listOf("chrome-a"), store.all().map { it.deviceId })
        store.useAccount("user-b")
        assertEquals(emptyList<LocalDevice>(), store.all())
    }

    @Test
    fun trustFromEarlierVersionsIsSplitByAccount() {
        val records = listOf("user-a" to "chrome-a", "user-b" to "chrome-b").map { (user, id) ->
            val dto = device(id)
            LocalDevice(user, id, 1, dto.encryptionPublicKey, dto.signingPublicKey, LocalTrust.ROOT)
        }
        storage.write(
            "trust-devices",
            CopyytJson.encodeToString(ListSerializer(LocalDevice.serializer()), records).toByteArray(),
        )

        val store = TrustStore(storage)
        store.useAccount("user-a")
        assertEquals(listOf("chrome-a"), store.all().map { it.deviceId })
        assertEquals(LocalTrust.ROOT, store.get("chrome-a")!!.trust)
        store.useAccount("user-b")
        assertNotNull(store.get("chrome-b"))
        assertNull(storage.read("trust-devices"))
    }
}
