*Fortify FPR file extractor

I've started using Fortify to analyse the code of our applications. As every Software Developement Lify Cycle (SDLC) we needed to get the result during the pipeline, but the image that we are using doesn't have the FPRUtility.

> stages:
>   - fortify
>
> fortify-sast-scancentral:
>   stage: fortify
>   image: 
>     name: fortifydocker/fortify-ci-tools:latest
> 

For this reason I decided to create this bash script to unzip the fpr file and analyse its results

> $ bash extract.bash -f scan.fpr

I saw in my investigations this logic and decided to use it in my code, if you have a different opinion, just contact me.


>   if ( impact >= 2.5 && probability >= 2.5 )
>   then
>     Critical
>   elseif ( impact >= 2.5" && probability <= 2.5 )
>   then
>     High
>   elseif ( impact <= 2.5 && probability >= 2.5 )
>   then
>     Medium
>   else
>     Low

Disclaimer: This script was made from me to me. It is provided “as is” without any warranty whatsoever, including the accuracy and comprehensiveness.
Copyright holder of this code may change the contents of this code at any time without prior notice, and copyright
holder disclaims any liability in relation to recipient’s use of this code.

