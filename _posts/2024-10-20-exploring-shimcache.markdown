---
layout: post
title:  "Exploring ShimCache: A Literature Review Across Windows Versions"
date:   2024-10-20 10:13:00 +1000
categories: Digital Forensics
---
## Preface
This blog is based on a report from my recent Digital Forensics unit, and it may contain grammatical and technical errors. No primary research or testing was conducted to verify the claims made. 

As much as I would love to personally verify each claim for validity and ensure that the report is error-free, time constraints don't currently allow for that, but I may revist this in the future. 

So, why am I publishing it in the first place?

I don't want my insecurities or need for perfection to hinder me from sharing my work. After all, the primary reason for starting this blog is to track my progress as I navigate through my cyber security journey. 

What good would it be to not make mistakes? The important thing is to learn from them and reflect on how far I've come.

## Abstract 
The ShimCache is a component of the Microsoft Windows Application Compatibility Infrastructure, introduced to address compatibility issues and to ensure that legacy programs remain functional with new releases of the Windows operating system (Understanding Shims, 2012). 

The shim acts as a proxy between outdated applications and the operating system, replacing incompatible code with updated or alternative code through a process known as shimming ("Shimcache: InfoSec Notes," n.d.). Files that have recently been shimmed are recorded in the ShimCache, which contains metadata of interest to investigators, such as the full file path, size, and last modified date (Parisi, 2015). 

In Windows XP and Windows Server 2003, the presence of a file in the shimcache could reliably indicate that the file had been executed. From Windows Vista through Windows 8.1, likely execution was indicated by the insert flag being set to the value 2. However, starting with Windows Vista, files were also added to the ShimCache when they were displayed while interactively browsing a directory, not just when they were executed (Davis, 2012). 

In Windows 10 and later versions, the insert flag was removed and replaced with an execution flag, which is the last 4 bytes of the cache entry. If this flag is set to 1, it may indicate that the file was executed, although this is not definitive (Peterson, 2024).

Complicating the analysis further is the shift to writing cache data only during system shutdown or reboot (Davis, 2012). This change has made it more challenging for investigators, especially those without specialised tools such as the Volatility plugin “shimcachemem,” which are needed to examine the cache while it is still in memory ("Shimcache: InfoSec Notes," n.d.). Additionally, the shimming process can be exploited by adversaries using techniques like living off the land (LOTL) to establish persistence, inject DLLs, and perform other malicious actions (MITRE ATT&CK, 2020).

Overall, the complexity and variability of analysing the shimcache, arising from the numerous Windows versions each with unique behaviours, lack of detailed internal documentation, finite size, and data rolling of the shimcache, complicate reliable analysis. Although the ShimCache can reliably indicate that a file was present on the system, confidently determining whether the file was executed requires ongoing research and testing. 

## Introduction
The Microsoft Windows Application Compatibility Infrastructure, also known as the Shim Infrastructure, was introduced in Windows XP (Parisi, 2015) to address compatibility issues with older programs to ensure they remain functional with new releases of the Microsoft operating system. This system acts as a proxy layer between these outdated applications and the new OS (Rocha, 2016). It identifies compatibility issues and resolves them through a process known as shimming. 

A shim is a small library that sits between two components to modify their behaviour, it “transparently intercepts an API, changes the parameters passed, handles the operation itself, or redirects the operation elsewhere (Marcho, 2019)”. Shims are an effective method of resolving incompatibility between applications and the operating system. They provide backwards compatibility enabling legacy applications to operate on newer versions of Windows by replacing problematic binaries. 

When an application requires external binaries, such as functions or data, it checks the Import Address Table (IAT), which is a table that contains pointers to the location of these binaries (Chen, 2022). The binaries returned from the IAT are queried against the Application Compatibility Database by the Shim Engine for any identified incompatibilities between the binary and the operating system. If any incompatibilities are found, the location of the binary returned by the IAT is intercepted and replaced with a compatible binary, completing the shimming process. 

The ShimCache, also known as the AppCompatCache, is stored in the Application Compatibility Database. Each ShimCache entry contains metadata about the files that have been shimmed. This metadata varies per operating system (Parisi, 2015), but generally includes information such as the full file path, file size, and last modified date. This information allows the operating system to identify which applications have already been analysed for compatibility issues, so it doesn’t need to perform a lookup in the Application Compatibility Database every time the application runs. If an application has been recently modified, the system can use the ShimCache to determine if a new lookup is required. This optimisation improves the performance of subsequent application launches. 

This artefact is of interest to digital forensic investigators because it can often be used to trace and analyse program execution or modifications, as well as details such as the full path and size of associated files, the existence of files on the system, and, in some cases, the execution order and time (Tuominen, 2023). On Windows Server operating systems, where Prefetch is disabled by default, the shimcache becomes an even more valuable source of evidence, serving as an alternative for tracking and analysing file activity (Rocha, 2016). 

## Technical Analysis
### Shim Process
This section discusses in further depth the process of shimming, from program execution to the addition of ShimCache entries. 

The Windows API is implemented using a collection of Dynamic-Link Libraries (DLL) which are essentially modules that “contain functions and data that can be used by [other] module[s]” ("Dynamic-link libraries (DLLs)", 2022). These DLLs encompass much of Windows core functionality and serve as a mechanism through which applications communicate and implement fundamental Windows services. One example is the Comdlg32 DLL which performs common dialog box related functions (What is a DLL, 2024). 

When an application calls a function provided by a certain DLL, the module is loaded, and the address of the function is stored in a table known as the Import Address Table (IAT). This table contains pointers to function addresses, enabling the application to directly access and execute the required functions. This has the benefit of performance optimisation as the application won’t need to repeatedly search for function addresses. Additionally, this structure promotes modularity and code reuse, as multiple applications can share the same DLL without needing to recompile the code or include it within their own binaries (Dynamic-Link Libraries, 2022). 

In the context of compatibility, this structure can be used to replace incompatible binaries with newer or alternative versions of DLLs without modifying or recompiling the application’s code. The replacement of the binaries is done by the Shim; it implements a form of application programming interface (API) hooking to redirect API calls from Windows to the Shim (Understanding Shims, 2012). The Shim modifies the address of the function resolved in the IAT and replaces it with a pointer to a function in the alternate shim code. 

Shimmed files are recorded in the ShimCache, which tracks files that have recently been shimmed and their metadata, including but not limited to the file path, size, last modified time, and execution flag. The cache uses a Least Recently Used (LRU) queue, placing the most recently shimmed files at the top and the oldest shim entries at the bottom (Parisi, 2015). Due to the cache’s limited size, older shim entries are replaced with newer entries when the cache is full. A process known as data rolling (Parisi, 2015). 

To determine if an application requires shimming, the Shim Engine will query the Application Compatibility Database, a database with the .sdb extension that contains a list of applications that have compatibility issues and require shimming. This process of looking up the application in the database and determining the appropriate shim to apply for each application is known as matching (Application Compatibility Database, 2021). 

### Shim Structure
#### Windows XP 32-bit 
In Windows XP 32-bit editions, the shimcache is stored in the registry path:

> HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatibility\AppCompatCache

The cache contains at most 96 entries, each 552-bytes in size. Entries are added to the cache when an “existing file's metadata has changed and re-executed, or a new file is executed”. The cache has a 400-byte header that must begin with the magic value 0xDEADBEEF and contains the number of shim entries and indexes (Davis, 2012). 

The entries include the full file path of the executed file, encompassing UNC paths and removable media (ShimCache, 2022). This attribute is present in every shim-compatible version of Windows, along with the $Standard_Information last modified timestamp. The last modified timestamp indicates when the contents of the file were last changed, which does not necessarily reflect the time the file was added to the shimcache or was executed (Parisi, 2015). For instance, executing a file, such as opening and reading a document, does not always modify its contents.

Additional attributes in the Windows XP 32-bit ShimCache entry include the file size and the "last update" time. The "last update" time may indicate the last time the file was executed, as this attribute is updated during execution. Unlike the "last modified" timestamp, which reflects changes to the file's contents, the "last update" time focuses on whether the file has been executed, regardless of whether its contents were altered (Tuominen, 2023).

#### Windows XP 64-bit and Windows Server 2003 
The Shim Infrastructure, particularly the method of storing entries, underwent significant changes from Windows XP 32-bit to the 64-bit editions and Windows Server 2003. One major change was the transition of the Shim engine from user mode to kernel mode. As a result, ShimCache entries were now read from kernel memory during system startup and written to the registry during shutdown or reboot (Davis, 2012). The registry path where these entries are stored, including in future versions of Windows, is:

> HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache

The cache can contain up to 512 entries, with entries being either 24 bytes on 32-bit systems or 32 bytes on 64-bit systems (Davis, 2012). Similar to 32-bit versions of Windows XP, entries are created when the file's metadata changes and the file is re-executed, a new file is executed, or when the file path changes, and the file is executed

again. The cache has an 8-byte header that contains the number of shim entries and must begin with the magic value 0xBADC0FFE (Davis, 2012).

These versions include the same attributes as those in the 32-bit version of Windows XP, except for the last update time, which has also been removed from future versions. 

#### Windows Vista and Windows Server 2008
The implementation of the shimcache in these versions of Windows is like the Windows XP 64-bit and Windows Server 2003 versions, except for the removal of the file size attribute and the addition of two 4-byte flags. 

These flags include the insert flag, which, if set to the value 2, likely indicate that the file was executed (Davis, 2012), and the Shim flag which is related to the Application Compatibility Database and specifies which Shim should be used for the executable. 

The cache retains the same header size and magic value as the previously mentioned version but increases the number of possible cache entries from 512 to 1024. Each entry is 24 bytes on 32-bit systems and 32 bytes on 64-bit systems.

A significant change in these versions is that files no longer need to be executed to be added to the shimcache; they can be added simply by interactively browsing a directory (Davis, 2012). Explorer.exe attempts to dynamically parse files visible in the window, so new files displayed resulting from scrolling or resizing the window are also included (Davis, 2021). This information could be useful for investigators, as it may indicate that a file was present on the system, even if it was not executed. However, this makes it difficult for investigators to reliably determine whether a file was executed based solely on its presence in the cache. 

#### Windows 7 and Windows Server 2008 R2 
The ShimCache in these versions have a header size of 128 bytes and consists of the magic value 0xBADC0FFE, number of entries, and cache statistics. The cache has a maximum of 1,024 entries, with entries being either 32 bytes on 32-bit systems or 48 bytes on 64-bit systems (Davis, 2012). The cache retains the same attributes as the previous version, with the addition of two new fields, “BlobSize” and “BlobOffset.” The purpose of these fields is currently unknown based on available research (Davis, 2012). 

#### Windows 8, 8.1 and Windows Server 2012 
These versions of Windows have a ShimCache header size of 128 bytes, containing a magic value of "00ts" for Windows 8 and "10ts" for Windows 8.1 through to current versions of Windows. The cache can store up to 1,024 entries, with entry sizes varying in byte size. Much of the cache's attributes remain consistent with previous versions (Davis, 2012). 

#### Windows 10, 11, and Windows Server 2016 
The ShimCache in these modern versions of Windows have a header size of 52 bytes, containing the magic value “10ts” and the number of ShimCache entries. The cache can store up to 1,024 entries, with entry sizes varying in byte size (Peterson, 2024). A significant change in these versions was the removal of the insert flag, which had been one potential method for indicating execution. However, an update from Eric Zimmerman, a SANS Institute instructor and author of several open-source digital forensic tools including AppCompatCacheParser (Zimmerman, 2023), revealed that in versions of Windows without the Insert Flag, execution could still potentially be indicated by analysing the last 4 bytes of an entry, referred to as the "execution flag," for the value 1 (Peterson, 2024).

Further research has supported this claim, revealing that executed files in the ShimCache had the expected value 1 set in the last 4 bytes of the entry. However, this wasn’t true for all cases. For example, where execution had been expected and observed such as “sass.exe, cmd.exe, and explorer.exe” did not result in an entry in the shimcache (Peterson, 2024). This suggests that while the execution flag can indicate a high likelihood of execution when set, its absence does not definitively rule out execution. 

### Limitations 
Due to the proprietary and closed-source nature of the Windows operating system, most research on the ShimCache artefact has been conducted through black box testing. In this approach, specific actions are performed, and their outcomes are recorded to determine if a particular action consistently produces a specific result. The addition of numerous versions, each with unique behaviours, creates a complex forensic ecosystem. This complexity imposes limitations, as assertions cannot be guaranteed due to the variability and lack of detailed internal documentation. Consequently, artefacts like the shimcache require ongoing research and testing before reliable guarantees can be made.

The vastly different behaviours across various versions require investigators to have not only a strong understanding of the artefact but also requires the consideration of the various contexts in which it is applied. An assertion that holds true in one version may not apply to another. For example, in Windows Vista and Windows Server 2008, the inclusion of a file in the ShimCache no longer guarantees execution, as files began to be added by interactively browsing a directory.

The shift from dynamically and immediately writing ShimCache entries to the registry in Windows XP 32-bit versions to writing cache data to the registry only during system shutdown or reboot in newer Windows versions, has made it more challenging for investigators. This change complicates cache analysis for those without specialised tools, such as the Volatility plugin “shimcachemem,” which are necessary to examine the cache while it is still in memory.

Another limitation of the ShimCache artefact is its finite size and data rolling. The ShimCache can hold a maximum of 96, 512, or 1024 entries, depending on the version of Windows. When the cache reaches its maximum capacity, older entries are overwritten to accommodate new ones, which could potentially erase evidence of significance.

Finally, it is not uncommon for adversaries to abuse legitimate Windows services to carry out attacks using a technique known as LOTL, where the attacker utilises tools already installed on the victim's environment (Bergmans, 2023). This also applies to the Windows Application Compatibility Infrastructure, specifically the shimming process, which can be exploited to establish persistence, inject DLLs, elevate privileges, and perform other malicious actions (MITRE ATT&CK, 2020). Consequently, an artefact that investigators use to discover malware could itself be exploited to execute malicious code. 


### References
Application Compatibility Database. (2021, January 7). Application compatibility database. Retrieved from https://learn.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-database

Bergmans, B. L. (2023, February 22). What AreLiving off the Land (LOTL) Attacks. Retrieved from https://www.crowdstrike.com/cybersecurity-101/living-off-the-land-attacks-lotl/

Chen, R. (2022, October 6). The Import Address Table is now write-protected, and what that means for rogue patching. Retrieved from https://devblogs.microsoft.com/oldnewthing/20221006-07/?p=107257

Davis, A. (2012). Leveraging the application compatibility cache in forensic investigations. Mandiant. Retrieved from https://web.archive.org/web/20210727184134/https://www.fireeye.com/content/dam/fireeye-www/services/freeware/shimcache-whitepaper.pdf

Davis, R. [13Cubed]. (2021, July 19). Let's talk about Shimcache - The most misunderstood artifact [Video]. YouTube. https://www.youtube.com/watch?v=7byz1dR_CLg

Dynamic-Link Libraries (Dynamic-Link Libraries). (2022). Retrieved from https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-libraries

Marcho, C. (2019, March 16). Demystifying Shims - or - Using the App Compat Toolkit to make your old stuff work with your new stuff. Retrieved from https://techcommunity.microsoft.com/t5/ask-the-performance-team/demystifying-shims-or-using-the-app-compat-toolkit-to-make-your/ba-p/374947

MITRE ATT&CK. (2020, January 24). T1546.011: Application shim injection. Retrieved from https://attack.mitre.org/techniques/T1546/011/

Parisi, T. (2015, June 17). Caching Out: The Value of Shimcache for Investigators. Retrieved from https://cloud.google.com/blog/topics/threat-intelligence/caching-out-the-val/

Peterson, M. (2024, August 21). AppCompatCache Deep Dive. Retrieved from https://nullsec.us/windows-10-11-appcompatcache-deep-dive/

Rocha, L. (2016, May 18). Digital Forensics – ShimCache Artifacts. Retrieved from https://countuponsecurity.com/2016/05/18/digital-forensics-shimcache-artifacts/

ShimCache. (2022). Retrieved from https://forensafe.com/blogs/shimcache.html

Shimcache: InfoSec Notes. (n.d.). Retrieved from https://notes.qazeer.io/dfir/windows/_artefacts_overview/shimcache

Tuominen, M. (2023, July 31). Novel analysis approaches for Windows Shimcache in forensic investigations (Master’s thesis). Aalto University. Retrieved from https://aaltodoc.aalto.fi/server/api/core/bitstreams/2e49da95-ce39-480b-a3e3-e5f9e73e77f0/content

Understanding Shims. (2012). Retrieved from https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-7/dd837644(v=ws.10)

What is a DLL. (2024). Retrieved from https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/dynamic-link-library

Zimmerman, E. [EricZimmerman]. (2023, July 8). AppCompatCacheParser [Source code]. GitHub. https://github.com/EricZimmerman/AppCompatCacheParser 