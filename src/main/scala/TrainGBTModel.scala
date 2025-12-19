import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types.DoubleType
import org.apache.spark.ml.feature.{VectorAssembler, StringIndexer, VectorIndexer}
import org.apache.spark.ml.classification.GBTClassifier
import org.apache.spark.ml.Pipeline

object TrainGBTModel {
  def main(args: Array[String]): Unit = {
    val spark = SparkSession.builder
      .appName("TrainGBTModel")
      .master("local[*]")
      .getOrCreate()
      
    spark.sparkContext.setLogLevel("WARN")
    println("🚀 Starting High-Tech GBT Model Training...")

    // 1. Load Data
    val rawDF = spark.read
      .option("header", "true")
      .option("inferSchema", "false") 
      .csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

    // 2. Feature Engineering
    val featuresDF = rawDF
      .withColumn("fwd_packets", trim(col(" Total Fwd Packets")).cast(DoubleType))
      .withColumn("bwd_packets", trim(col(" Total Backward Packets")).cast(DoubleType))
      .withColumn("flow_iat_mean", trim(col(" Flow IAT Mean")).cast(DoubleType))
      .withColumn("fwd_pkt_len_mean", trim(col(" Fwd Packet Length Mean")).cast(DoubleType))
      .withColumn("bwd_pkt_len_mean", trim(col(" Bwd Packet Length Mean")).cast(DoubleType))
      .select("fwd_packets", "bwd_packets", "flow_iat_mean", "fwd_pkt_len_mean", "bwd_pkt_len_mean", " Label")
      .na.drop() 

    // 3. Build Advanced Pipeline
    val labelIndexer = new StringIndexer()
      .setInputCol(" Label")
      .setOutputCol("label") 

    val assembler = new VectorAssembler()
      .setInputCols(Array("fwd_packets", "bwd_packets", "flow_iat_mean", "fwd_pkt_len_mean", "bwd_pkt_len_mean"))
      .setOutputCol("features")
      
    // Automatically identify categorical features for the tree
    val featureIndexer = new VectorIndexer()
      .setInputCol("features")
      .setOutputCol("indexedFeatures")
      .setMaxCategories(4)

    // GBT Classifier (The "High Tech" part)
    val gbt = new GBTClassifier()
      .setLabelCol("label")
      .setFeaturesCol("indexedFeatures")
      .setMaxIter(10) // Fast training
      .setStepSize(0.1)

    val pipeline = new Pipeline()
      .setStages(Array(labelIndexer, assembler, featureIndexer, gbt))
      
    // 4. Train
    println("Training Gradient-Boosted Tree Model...")
    val model = pipeline.fit(featuresDF)

    // 5. Save
    model.write.overwrite().save("my_gbt_model")

    println("---".repeat(20))
    println("✅ GBT Model Trained & Saved!")
    println("---".repeat(20))
    
    // Check what prediction ID 'DDoS' got (usually 1.0)
    val predictions = model.transform(featuresDF)
    predictions.groupBy(" Label", "prediction").count().show()
    
    spark.stop()
  }
}