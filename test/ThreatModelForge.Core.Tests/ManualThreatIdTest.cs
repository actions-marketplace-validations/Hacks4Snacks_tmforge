namespace ThreatModelForge.Core.Tests
{
    using System;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.KnowledgeBase;

    /// <summary>
    /// Covers the reserved manual-threat identity namespace: what an author is allowed to name a
    /// threat, and the guarantee that the same input always yields the same id.
    /// </summary>
    [TestClass]
    public class ManualThreatIdTest
    {
        /// <summary>A minted id lands in the reserved namespace and is distinct each time.</summary>
        [TestMethod]
        public void CreateProducesIdInReservedNamespace()
        {
            string id = ManualThreatId.Create();

            Assert.IsTrue(ManualThreatId.IsManual(id), id);
            Assert.AreNotEqual(ManualThreatId.Create(), id, "Each generated id must be distinct.");
        }

        /// <summary>Manual detection is case-insensitive and does not claim generated ids.</summary>
        [TestMethod]
        public void IsManualIgnoresCaseAndRejectsOtherKeys()
        {
            Assert.IsTrue(ManualThreatId.IsManual("manual:abc"));
            Assert.IsTrue(ManualThreatId.IsManual("MANUAL:abc"));
            Assert.IsFalse(ManualThreatId.IsManual(null));
            Assert.IsFalse(ManualThreatId.IsManual(string.Empty));
            Assert.IsFalse(ManualThreatId.IsManual("d6f1c0e2ab114b0f9e0d2f1a3b4c5d6e:RULE-001"));
        }

        /// <summary>The native identity is reproducible and distinct without replacing the author's key.</summary>
        [TestMethod]
        public void NativeTypeIdentityIsStableAndRecognizedByMtmt()
        {
            string native = ManualThreatId.ToNativeTypeId("manual:Review-T-001");

            Assert.IsTrue(ManualThreatId.IsNativeTypeId(native));
            Assert.AreEqual(38, native.Length);
            Assert.AreEqual(native, ManualThreatId.ToNativeTypeId("MANUAL:review-t-001"));
            Assert.AreNotEqual(native, ManualThreatId.ToNativeTypeId("manual:Review-T-002"));
            Assert.IsTrue(Guid.TryParseExact(native.Substring(2), "D", out _));
        }

        /// <summary>A native identity cannot be allocated for a generated or empty key.</summary>
        /// <param name="key">The invalid register key.</param>
        [TestMethod]
        [DataRow("")]
        [DataRow("manual:")]
        [DataRow("source:TM1023")]
        [DataRow(null)]
        public void NativeTypeIdentityRequiresManualKey(string? key)
        {
            Assert.Throws<ArgumentException>(() => ManualThreatId.ToNativeTypeId(key!));
        }

        /// <summary>A rule name or an invalid BS-prefixed string is not a native user-defined identity.</summary>
        /// <param name="typeId">The non-native type id.</param>
        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("TM1023")]
        [DataRow("BSmanual:Review-T-001")]
        [DataRow("BS11111111222243338444555555555555")]
        [DataRow("BSxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")]
        public void NativeTypeDetectionRejectsOtherValues(string? typeId)
        {
            Assert.IsFalse(ManualThreatId.IsNativeTypeId(typeId));
        }

        /// <summary>The prefix is optional on input, so an author cannot create two ids by accident.</summary>
        /// <param name="supplied">The author's spelling of the id.</param>
        [TestMethod]
        [DataRow("login-bypass")]
        [DataRow("manual:login-bypass")]
        [DataRow("  manual:login-bypass  ")]
        [DataRow("MANUAL:login-bypass")]
        public void TryCanonicalizeTreatsPrefixAsOptional(string supplied)
        {
            Assert.IsTrue(ManualThreatId.TryCanonicalize(supplied, out string id, out string? error), error);
            Assert.AreEqual("manual:login-bypass", id);
            Assert.IsNull(error);
        }

        /// <summary>The author's own casing of the id is preserved.</summary>
        [TestMethod]
        public void TryCanonicalizePreservesAuthorCase()
        {
            Assert.IsTrue(ManualThreatId.TryCanonicalize("Login_Bypass.V2", out string id, out _));

            Assert.AreEqual("manual:Login_Bypass.V2", id);
        }

        /// <summary>Canonicalizing an already-canonical id is a no-op.</summary>
        [TestMethod]
        public void TryCanonicalizeIsIdempotent()
        {
            Assert.IsTrue(ManualThreatId.TryCanonicalize("login-bypass", out string once, out _));
            Assert.IsTrue(ManualThreatId.TryCanonicalize(once, out string twice, out _));

            Assert.AreEqual(once, twice);
        }

        /// <summary>An id with nothing after the prefix is refused.</summary>
        /// <param name="supplied">The author's spelling of the id.</param>
        [TestMethod]
        [DataRow("")]
        [DataRow("   ")]
        [DataRow("manual:")]
        [DataRow(null)]
        public void TryCanonicalizeRejectsEmptyLocalPart(string? supplied)
        {
            Assert.IsFalse(ManualThreatId.TryCanonicalize(supplied, out string id, out string? error));
            Assert.AreEqual(string.Empty, id);
            Assert.IsNotNull(error);
        }

        /// <summary>Characters that make an id ambiguous to quote or review are refused, and named.</summary>
        /// <param name="supplied">The author's spelling of the id.</param>
        /// <param name="offender">The character expected to be named in the error.</param>
        [TestMethod]
        [DataRow("login bypass", ' ')]
        [DataRow("login/bypass", '/')]
        [DataRow("login\tbypass", '\t')]
        [DataRow("login\u00e9", '\u00e9')]
        public void TryCanonicalizeRejectsCharactersThatMakeAnIdAmbiguous(string supplied, char offender)
        {
            Assert.IsFalse(ManualThreatId.TryCanonicalize(supplied, out _, out string? error));

            Assert.IsNotNull(error);
            StringAssert.Contains(error, offender.ToString());
        }

        /// <summary>The namespace separator cannot appear in the author's portion of the id.</summary>
        [TestMethod]
        public void TryCanonicalizeRejectsAnExtraNamespaceSeparator()
        {
            // ':' separates the namespace from the id. Allowing it would let an author write an id
            // that reads like a generated one.
            Assert.IsFalse(ManualThreatId.TryCanonicalize("manual:a:b", out _, out string? error));

            Assert.IsNotNull(error);
        }

        /// <summary>An over-long id is refused rather than truncated.</summary>
        [TestMethod]
        public void TryCanonicalizeRejectsIdLongerThanTheLimit()
        {
            string local = new string('a', ManualThreatId.MaxLocalLength + 1);

            Assert.IsFalse(ManualThreatId.TryCanonicalize(local, out _, out string? error));

            Assert.IsNotNull(error);
        }

        /// <summary>An id exactly at the limit is accepted.</summary>
        [TestMethod]
        public void TryCanonicalizeAcceptsIdAtTheLimit()
        {
            string local = new string('a', ManualThreatId.MaxLocalLength);

            Assert.IsTrue(ManualThreatId.TryCanonicalize(local, out string id, out string? error), error);

            Assert.AreEqual(ManualThreatId.Prefix + local, id);
        }

        /// <summary>A minted id survives canonicalization unchanged.</summary>
        [TestMethod]
        public void TryCanonicalizeAcceptsAGeneratedIdUnchanged()
        {
            string created = ManualThreatId.Create();

            Assert.IsTrue(ManualThreatId.TryCanonicalize(created, out string id, out _));

            Assert.AreEqual(created, id);
        }
    }
}
