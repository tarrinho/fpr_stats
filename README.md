**Fortify FPR file extractor**

I've started using Fortify to analyse the code of our applications. Like every Software Developement Life Cycle (SDLC) we needed to get the result during the pipeline, but the image that we are using doesn't have the FPRUtility.

```plaintext
 stages:
   - fortify

 fortify-sast-scancentral:
   stage: fortify
   image:
     name: fortifydocker/fortify-ci-tools:latest
```

For this reason I decided to create this bash script to unzip the fpr file and analyse its results

```plaintext
$ bash extract.bash -f scan.fpr
```

I saw in my investigations this logic and decided to use it in my code. If you have a different opinion, just contact me.

```plaintext

   if ( impact >= 2.5 && probability >= 2.5 )
   then
     Critical
   elseif ( impact >= 2.5" && probability <= 2.5 )
   then
     High
   elseif ( impact <= 2.5 && probability >= 2.5 )
   then
     Medium
   else
     Low
```

**Requirements**
 - unzip
 - bc 
 - xmllint

To install just do :
> apt get install unzip xmllint bc -y

Disclaimer: This script was made by me for me. It is provided “as is” without any warranty whatsoever, including accuracy and comprehensiveness.  
The copyright holder of this code may change the contents of this code at any time without prior notice, and the copyright holder disclaims any liability in relation to the recipient’s use of this code.
