// Native AOT compatibility harness for the Sigstore and Tuf libraries.
//
// This project exists to be published with PublishAot=true. Both libraries are
// listed as TrimmerRootAssembly items in the csproj, so ILC analyses every public
// API they expose rather than only the members reached from this entry point. Any
// trim or AOT warning (IL2xxx/IL3xxx) fails the build via TreatWarningsAsErrors.
//
// The body below is deliberately trivial: the rooting in the csproj, not the code
// here, is what provides the coverage.

Console.WriteLine("Sigstore and Tuf published successfully with native AOT.");
