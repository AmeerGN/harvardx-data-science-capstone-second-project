# HarvardX Data Science: Capstone - Second Project

This is the second project of the Capstone course which is the ninth and last course of HarvardX Data Science series.

## Project Structure

It is an R project structured as: data folder, R script file, R Markdown report file.

### Dataset

The dataset for this project is [NSL-KDD dataset](https://www.unb.ca/cic/datasets/nsl.html). It is downloaded and stored in the `data` folder.

### R Script File

`intrusion_detection_code.R` contains the R script used to read and analyze the dataset, preprocess it, train the models, and show the prediction results.

### R Markdown Report File

`intrusion_detection_system.Rmd` contains the detailed report of this project, including its goals, methodology, and results. This report should be runnable, and must be consistent with the R script file.  
To generate a PDF version of this report, we use the following command in R Console:  
```R
rmarkdown::render("intrusion_detection_system.Rmd", "pdf_document")
```