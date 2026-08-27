// Copyright (c) Sigstore contributors. Licensed under the Apache 2.0 license.
//
// Repo-wide test helpers bridging the handful of xUnit assertions that have no
// direct MSTest equivalent. Linked into every *.Tests project via
// Directory.Build.props so the source of truth lives once here.

using System.Collections;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sigstore.Testing;

internal static class TestSeq
{
    /// <summary>
    /// Sequence-equality assertion over <see cref="IEnumerable{T}"/>. MSTest's
    /// <c>Assert.AreEqual</c> uses <see cref="EqualityComparer{T}.Default"/>, which on
    /// array and collection types collapses to reference equality, and
    /// <c>CollectionAssert.AreEqual</c> requires <see cref="ICollection"/> rather than
    /// <see cref="IEnumerable{T}"/>. This materialises both sides and delegates.
    /// </summary>
    public static void AreEqual<T>(IEnumerable<T>? expected, IEnumerable<T>? actual, string? message = null)
        => CollectionAssert.AreEqual(expected?.ToList(), actual?.ToList(), message ?? string.Empty);

    /// <summary>
    /// Assert that <paramref name="source"/> contains exactly one element, and return it.
    /// MSTest's <c>Assert.ContainsSingle</c> family returns <see langword="void"/>, so this
    /// wraps it and returns the element for callers that bind it.
    /// </summary>
    public static T Single<T>(IEnumerable<T> source)
    {
        var list = source.ToList();
        Assert.HasCount(1, list);
        return list[0];
    }

    /// <summary>
    /// Assert that exactly one element of <paramref name="source"/> matches
    /// <paramref name="predicate"/>, and return that element.
    /// </summary>
    public static T Single<T>(IEnumerable<T> source, Func<T, bool> predicate)
    {
        var matches = source.Where(predicate).ToList();
        Assert.HasCount(1, matches);
        return matches[0];
    }

    /// <summary>
    /// Assert that <paramref name="value"/> is of type <typeparamref name="T"/> and return
    /// the cast value. MSTest's <c>Assert.IsInstanceOfType&lt;T&gt;</c> returns
    /// <see langword="void"/>.
    /// </summary>
    public static T IsType<T>(object? value)
    {
        Assert.IsInstanceOfType<T>(value);
        return (T)value!;
    }

    /// <summary>
    /// Apply <paramref name="action"/> to every element of <paramref name="source"/>, so each
    /// element can be asserted individually.
    /// </summary>
    public static void All<T>(IEnumerable<T> source, Action<T> action)
    {
        foreach (var item in source)
        {
            action(item);
        }
    }
}
